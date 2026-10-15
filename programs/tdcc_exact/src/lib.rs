//! TDCC Exact on Solana: the escrow, the provider stakes and the receipts of oracle jobs.
//!
//! A job's life (slots, from the job's `open_job`):
//!
//! ```text
//!     open_job ──► commit_receipt ──► reveal_receipt ──► settle            (80% host, 20% TDCC)
//!     (renter)     (provider, until    (provider, after    (anyone, after the
//!                   commit_deadline)    commit_deadline)    challenge window)
//!                                            │
//!                                            └──► challenge ──► slash      (arbiter: refund the
//!                                                 (verifier)    │           renter, half the stake
//!                                                               │           to the verifier, the
//!                                                               │           rest to TDCC)
//!                                                               └──► dismiss ──► settle
//!                                                                    (one challenge per job)
//! ```
//!
//! A provider that commits but never reveals (or never commits) lets the renter take the
//! escrow back after the reveal deadline (`expire`).
//!
//! The receipt is posted in two phases against the copy attack (tdcc_exact/commit.py): honest
//! runs post the same fingerprint, so the provider first commits to
//! SHA-256(tag || fingerprint || provider key || salt) and reveals only after the commit
//! deadline, when copying is too late.
//!
//! Who decides a challenge: for now an arbiter (the config's admin, TDCC) signs `slash` or
//! `dismiss` after the off-chain bisection (tdcc_exact/dispute.py) names the faulty step; the
//! step is in the `Slashed` event. The on-chain bisection game is TODO.md item 6.
//!
//! The arithmetic is tdcc_exact/settle.py's: shares in basis points, rounded down, the
//! remainder to TDCC (tests/data/exact_settle_vectors.json is checked by both).

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, TransferChecked};
use solana_sha256_hasher::hashv;

declare_id!("HzpKeqHLg7Mmjh1JmGymef7Z7hf3JXhaagp6UgTSH24A");

pub const COMMIT_TAG: &[u8] = b"tdcc-exact/commit/v1";

pub mod math {
    pub const BPS: u64 = 10_000;

    /// amount * bps / 10000, rounded down.
    pub fn share(amount: u64, bps: u16) -> u64 {
        ((amount as u128) * (bps as u128) / (BPS as u128)) as u64
    }

    /// (host, tdcc) of a settled job's price.
    pub fn accept(price: u64, host_bps: u16) -> (u64, u64) {
        let host = share(price, host_bps);
        (host, price - host)
    }

    /// (verifier, tdcc) of a slashed stake.
    pub fn slash(stake: u64, verifier_bps: u16) -> (u64, u64) {
        let v = share(stake, verifier_bps);
        (v, stake - v)
    }
}

/// SHA-256(tag || fingerprint || provider || salt), as tdcc_exact.commit.commitment.
pub fn commitment(fingerprint: &[u8; 32], provider: &Pubkey, salt: &[u8; 32]) -> [u8; 32] {
    hashv(&[COMMIT_TAG, fingerprint, provider.as_ref(), salt]).to_bytes()
}

#[program]
pub mod tdcc_exact {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, params: ConfigParams) -> Result<()> {
        require!(params.host_bps as u64 <= math::BPS, ExactError::BadParams);
        require!(
            params.verifier_bps as u64 <= math::BPS,
            ExactError::BadParams
        );
        let c = &mut ctx.accounts.config;
        c.admin = ctx.accounts.admin.key();
        c.mint = ctx.accounts.mint.key();
        c.treasury = ctx.accounts.treasury.key();
        c.vault = ctx.accounts.vault.key();
        c.host_bps = params.host_bps;
        c.verifier_bps = params.verifier_bps;
        c.commit_window = params.commit_window;
        c.challenge_window = params.challenge_window;
        c.min_stake = params.min_stake;
        c.unstake_cooldown = params.unstake_cooldown;
        c.bump = ctx.bumps.config;
        c.vault_bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn register_provider(ctx: Context<RegisterProvider>) -> Result<()> {
        let p = &mut ctx.accounts.provider;
        p.owner = ctx.accounts.owner.key();
        p.stake = 0;
        p.open_jobs = 0;
        p.unlock_slot = 0;
        p.bump = ctx.bumps.provider;
        Ok(())
    }

    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        require!(amount > 0, ExactError::BadParams);
        let a = &ctx.accounts;
        pay_in(
            &a.token_program,
            &a.from,
            &a.vault,
            &a.mint,
            &a.owner,
            amount,
        )?;
        let p = &mut ctx.accounts.provider;
        p.stake = p.stake.checked_add(amount).ok_or(ExactError::Overflow)?;
        p.unlock_slot = 0; // staking again cancels a pending unstake
        emit!(Staked {
            provider: p.owner,
            amount,
            stake: p.stake
        });
        Ok(())
    }

    pub fn request_unstake(ctx: Context<ProviderOnly>) -> Result<()> {
        let cooldown = ctx.accounts.config.unstake_cooldown;
        let p = &mut ctx.accounts.provider;
        p.unlock_slot = Clock::get()?
            .slot
            .checked_add(cooldown)
            .ok_or(ExactError::Overflow)?;
        Ok(())
    }

    pub fn unstake(ctx: Context<Unstake>) -> Result<()> {
        let now = Clock::get()?.slot;
        let p = &ctx.accounts.provider;
        require!(
            p.unlock_slot != 0 && now >= p.unlock_slot,
            ExactError::StakeLocked
        );
        require!(p.open_jobs == 0, ExactError::StakeLocked);
        let amount = p.stake;
        let a = &ctx.accounts;
        pay_out(
            &a.token_program,
            &a.vault,
            &a.to,
            &a.mint,
            &a.config,
            amount,
        )?;
        let p = &mut ctx.accounts.provider;
        p.stake = 0;
        p.unlock_slot = 0;
        Ok(())
    }

    pub fn open_job(
        ctx: Context<OpenJob>,
        job_id: u64,
        job_digest: [u8; 32],
        model_hash: [u8; 32],
        price: u64,
    ) -> Result<()> {
        let c = &ctx.accounts.config;
        let p = &ctx.accounts.provider;
        // a free job would tie up a provider (an open job locks its stake) at no cost
        require!(price > 0, ExactError::BadParams);
        require!(
            p.stake >= c.min_stake && p.unlock_slot == 0,
            ExactError::ProviderNotStaked
        );
        let a = &ctx.accounts;
        pay_in(
            &a.token_program,
            &a.from,
            &a.vault,
            &a.mint,
            &a.renter,
            price,
        )?;
        let now = Clock::get()?.slot;
        let commit_deadline = now
            .checked_add(c.commit_window)
            .ok_or(ExactError::Overflow)?;
        let j = &mut ctx.accounts.job;
        j.config = ctx.accounts.config.key();
        j.renter = ctx.accounts.renter.key();
        j.provider = ctx.accounts.provider.owner;
        j.job_id = job_id;
        j.job_digest = job_digest;
        j.model_hash = model_hash;
        j.price = price;
        j.state = JobState::Open;
        j.opened_slot = now;
        j.commit_deadline = commit_deadline;
        j.reveal_deadline = commit_deadline
            .checked_add(c.commit_window)
            .ok_or(ExactError::Overflow)?;
        j.challenge_deadline = 0;
        j.commitment = [0; 32];
        j.fingerprint = [0; 32];
        j.trace_root = [0; 32];
        j.checkpoints = 0;
        j.verifier = Pubkey::default();
        j.verifier_fingerprint = [0; 32];
        j.bump = ctx.bumps.job;
        let p = &mut ctx.accounts.provider;
        p.open_jobs = p.open_jobs.checked_add(1).ok_or(ExactError::Overflow)?;
        emit!(JobOpened {
            job: j.key(),
            renter: j.renter,
            provider: j.provider,
            price,
            job_digest
        });
        Ok(())
    }

    pub fn commit_receipt(ctx: Context<ProviderJob>, commitment: [u8; 32]) -> Result<()> {
        let j = &mut ctx.accounts.job;
        require!(j.state == JobState::Open, ExactError::WrongState);
        require!(
            Clock::get()?.slot <= j.commit_deadline,
            ExactError::WindowClosed
        );
        j.commitment = commitment;
        j.state = JobState::Committed;
        emit!(ReceiptCommitted {
            job: j.key(),
            commitment
        });
        Ok(())
    }

    pub fn reveal_receipt(
        ctx: Context<ProviderJob>,
        fingerprint: [u8; 32],
        salt: [u8; 32],
        model_hash: [u8; 32],
        trace_root: [u8; 32],
        checkpoints: u32,
    ) -> Result<()> {
        let challenge_window = ctx.accounts.config.challenge_window;
        let owner = ctx.accounts.owner.key();
        let j = &mut ctx.accounts.job;
        let now = Clock::get()?.slot;
        require!(j.state == JobState::Committed, ExactError::WrongState);
        require!(now > j.commit_deadline, ExactError::WindowOpen);
        require!(now <= j.reveal_deadline, ExactError::WindowClosed);
        require!(
            commitment(&fingerprint, &owner, &salt) == j.commitment,
            ExactError::BadReveal
        );
        require!(model_hash == j.model_hash, ExactError::ModelMismatch);
        j.fingerprint = fingerprint;
        j.trace_root = trace_root;
        j.checkpoints = checkpoints;
        j.state = JobState::Revealed;
        j.challenge_deadline = now
            .checked_add(challenge_window)
            .ok_or(ExactError::Overflow)?;
        emit!(ReceiptRevealed {
            job: j.key(),
            fingerprint,
            trace_root,
            checkpoints
        });
        Ok(())
    }

    pub fn challenge(ctx: Context<Challenge>, fingerprint: [u8; 32]) -> Result<()> {
        let j = &mut ctx.accounts.job;
        require!(j.state == JobState::Revealed, ExactError::WrongState);
        require!(
            Clock::get()?.slot <= j.challenge_deadline,
            ExactError::WindowClosed
        );
        require!(fingerprint != j.fingerprint, ExactError::SameFingerprint);
        // one challenge per job: once the arbiter dismissed one, the receipt stands
        require!(j.verifier == Pubkey::default(), ExactError::AlreadyChallenged);
        j.verifier = ctx.accounts.verifier.key();
        j.verifier_fingerprint = fingerprint;
        j.state = JobState::Challenged;
        emit!(Challenged {
            job: j.key(),
            verifier: j.verifier,
            fingerprint
        });
        Ok(())
    }

    pub fn settle(ctx: Context<Settle>) -> Result<()> {
        let c = &ctx.accounts.config;
        let j = &ctx.accounts.job;
        require!(j.state == JobState::Revealed, ExactError::WrongState);
        require!(
            Clock::get()?.slot > j.challenge_deadline,
            ExactError::WindowOpen
        );
        let (host, fee) = math::accept(j.price, c.host_bps);
        let a = &ctx.accounts;
        pay_out(
            &a.token_program,
            &a.vault,
            &a.provider_token,
            &a.mint,
            &a.config,
            host,
        )?;
        pay_out(
            &a.token_program,
            &a.vault,
            &a.treasury,
            &a.mint,
            &a.config,
            fee,
        )?;
        let job_key = ctx.accounts.job.key();
        ctx.accounts.job.state = JobState::Settled;
        let p = &mut ctx.accounts.provider;
        p.open_jobs = p.open_jobs.saturating_sub(1);
        emit!(Settled {
            job: job_key,
            provider: p.owner,
            host,
            fee
        });
        Ok(())
    }

    pub fn slash(ctx: Context<Slash>, divergence_index: u32, fault_step: u64) -> Result<()> {
        let c = &ctx.accounts.config;
        let j = &ctx.accounts.job;
        require!(j.state == JobState::Challenged, ExactError::WrongState);
        let stake = ctx.accounts.provider.stake;
        let (to_verifier, to_tdcc) = math::slash(stake, c.verifier_bps);
        let price = j.price;
        let a = &ctx.accounts;
        pay_out(
            &a.token_program,
            &a.vault,
            &a.renter_token,
            &a.mint,
            &a.config,
            price,
        )?;
        pay_out(
            &a.token_program,
            &a.vault,
            &a.verifier_token,
            &a.mint,
            &a.config,
            to_verifier,
        )?;
        pay_out(
            &a.token_program,
            &a.vault,
            &a.treasury,
            &a.mint,
            &a.config,
            to_tdcc,
        )?;
        let job_key = ctx.accounts.job.key();
        let verifier = ctx.accounts.job.verifier;
        ctx.accounts.job.state = JobState::Slashed;
        let p = &mut ctx.accounts.provider;
        p.stake = 0;
        p.open_jobs = p.open_jobs.saturating_sub(1);
        emit!(Slashed {
            job: job_key,
            provider: p.owner,
            verifier,
            refunded: price,
            to_verifier,
            to_tdcc,
            divergence_index,
            fault_step,
        });
        Ok(())
    }

    /// The arbiter found the challenge wrong: the job settles as if unchallenged.
    pub fn dismiss(ctx: Context<Dismiss>) -> Result<()> {
        let j = &mut ctx.accounts.job;
        require!(j.state == JobState::Challenged, ExactError::WrongState);
        j.state = JobState::Revealed;
        j.challenge_deadline = Clock::get()?.slot;
        emit!(Dismissed {
            job: j.key(),
            verifier: j.verifier
        });
        Ok(())
    }

    /// No reveal by the reveal deadline: the renter takes the escrow back.
    pub fn expire(ctx: Context<Expire>) -> Result<()> {
        let j = &ctx.accounts.job;
        require!(
            j.state == JobState::Open || j.state == JobState::Committed,
            ExactError::WrongState
        );
        require!(
            Clock::get()?.slot > j.reveal_deadline,
            ExactError::WindowOpen
        );
        let price = j.price;
        let a = &ctx.accounts;
        pay_out(
            &a.token_program,
            &a.vault,
            &a.renter_token,
            &a.mint,
            &a.config,
            price,
        )?;
        ctx.accounts.job.state = JobState::Expired;
        let p = &mut ctx.accounts.provider;
        p.open_jobs = p.open_jobs.saturating_sub(1);
        Ok(())
    }
}

// ------------------------------------------------------------------------- token moves
fn pay_in<'info>(
    token_program: &Program<'info, Token>,
    from: &Account<'info, TokenAccount>,
    vault: &Account<'info, TokenAccount>,
    mint: &Account<'info, Mint>,
    authority: &Signer<'info>,
    amount: u64,
) -> Result<()> {
    token::transfer_checked(
        CpiContext::new(
            token_program.key(),
            TransferChecked {
                from: from.to_account_info(),
                mint: mint.to_account_info(),
                to: vault.to_account_info(),
                authority: authority.to_account_info(),
            },
        ),
        amount,
        mint.decimals,
    )
}

fn pay_out<'info>(
    token_program: &Program<'info, Token>,
    vault: &Account<'info, TokenAccount>,
    to: &Account<'info, TokenAccount>,
    mint: &Account<'info, Mint>,
    config: &Account<'info, Config>,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let seeds: &[&[u8]] = &[b"config", config.admin.as_ref(), &[config.bump]];
    token::transfer_checked(
        CpiContext::new_with_signer(
            token_program.key(),
            TransferChecked {
                from: vault.to_account_info(),
                mint: mint.to_account_info(),
                to: to.to_account_info(),
                authority: config.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        mint.decimals,
    )
}

// ------------------------------------------------------------------------- state
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct ConfigParams {
    pub host_bps: u16,
    pub verifier_bps: u16,
    pub commit_window: u64,
    pub challenge_window: u64,
    pub min_stake: u64,
    pub unstake_cooldown: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey, // the arbiter of challenges (for now: TDCC)
    pub mint: Pubkey,  // USDC
    pub treasury: Pubkey,
    pub vault: Pubkey, // holds every escrow and every stake
    pub host_bps: u16,
    pub verifier_bps: u16,
    pub commit_window: u64, // slots
    pub challenge_window: u64,
    pub min_stake: u64,
    pub unstake_cooldown: u64,
    pub bump: u8,
    pub vault_bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Provider {
    pub owner: Pubkey,
    pub stake: u64,
    pub open_jobs: u32,
    pub unlock_slot: u64, // 0: no unstake requested
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace, Debug)]
pub enum JobState {
    Open,
    Committed,
    Revealed,
    Challenged,
    Settled,
    Slashed,
    Expired,
}

#[account]
#[derive(InitSpace)]
pub struct Job {
    pub config: Pubkey,
    pub renter: Pubkey,
    pub provider: Pubkey,
    pub job_id: u64,
    pub job_digest: [u8; 32], // tdcc_exact.oracle.Job.digest
    pub model_hash: [u8; 32], // the registry's pinned image hash
    pub price: u64,
    pub state: JobState,
    pub opened_slot: u64,
    pub commit_deadline: u64,
    pub reveal_deadline: u64,
    pub challenge_deadline: u64,
    pub commitment: [u8; 32],
    pub fingerprint: [u8; 32],
    pub trace_root: [u8; 32],
    pub checkpoints: u32,
    pub verifier: Pubkey,
    pub verifier_fingerprint: [u8; 32],
    pub bump: u8,
}

// ------------------------------------------------------------------------- accounts
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + Config::INIT_SPACE, seeds = [b"config", admin.key().as_ref()], bump)]
    pub config: Account<'info, Config>,
    pub mint: Account<'info, Mint>,
    #[account(init, payer = admin, seeds = [b"vault", config.key().as_ref()], bump,
              token::mint = mint, token::authority = config)]
    pub vault: Account<'info, TokenAccount>,
    #[account(token::mint = mint)]
    pub treasury: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterProvider<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(init, payer = owner, space = 8 + Provider::INIT_SPACE,
              seeds = [b"provider", config.key().as_ref(), owner.key().as_ref()], bump)]
    pub provider: Account<'info, Provider>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump, has_one = mint, has_one = vault)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"provider", config.key().as_ref(), owner.key().as_ref()], bump = provider.bump)]
    pub provider: Account<'info, Provider>,
    pub mint: Account<'info, Mint>,
    #[account(mut, token::mint = mint, token::authority = owner)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ProviderOnly<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"provider", config.key().as_ref(), owner.key().as_ref()], bump = provider.bump)]
    pub provider: Account<'info, Provider>,
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump, has_one = mint, has_one = vault)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"provider", config.key().as_ref(), owner.key().as_ref()], bump = provider.bump)]
    pub provider: Account<'info, Provider>,
    pub mint: Account<'info, Mint>,
    #[account(mut, token::mint = mint, token::authority = owner)]
    pub to: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(job_id: u64)]
pub struct OpenJob<'info> {
    #[account(mut)]
    pub renter: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump, has_one = mint, has_one = vault)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"provider", config.key().as_ref(), provider.owner.as_ref()], bump = provider.bump)]
    pub provider: Account<'info, Provider>,
    #[account(init, payer = renter, space = 8 + Job::INIT_SPACE,
              seeds = [b"job", config.key().as_ref(), renter.key().as_ref(), &job_id.to_le_bytes()], bump)]
    pub job: Account<'info, Job>,
    pub mint: Account<'info, Mint>,
    #[account(mut, token::mint = mint, token::authority = renter)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ProviderJob<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config, constraint = job.provider == owner.key() @ ExactError::NotYourJob)]
    pub job: Account<'info, Job>,
}

#[derive(Accounts)]
pub struct Challenge<'info> {
    pub verifier: Signer<'info>,
    #[account(mut, constraint = job.provider != verifier.key() @ ExactError::NotYourJob)]
    pub job: Account<'info, Job>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump, has_one = mint, has_one = vault,
              has_one = treasury)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config, constraint = job.provider == provider.owner @ ExactError::NotYourJob)]
    pub job: Account<'info, Job>,
    #[account(mut, seeds = [b"provider", config.key().as_ref(), provider.owner.as_ref()], bump = provider.bump)]
    pub provider: Account<'info, Provider>,
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, token::mint = mint, token::authority = provider.owner)]
    pub provider_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub treasury: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Slash<'info> {
    pub admin: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump, has_one = admin, has_one = mint,
              has_one = vault, has_one = treasury)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config, constraint = job.provider == provider.owner @ ExactError::NotYourJob)]
    pub job: Account<'info, Job>,
    #[account(mut, seeds = [b"provider", config.key().as_ref(), provider.owner.as_ref()], bump = provider.bump)]
    pub provider: Account<'info, Provider>,
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, token::mint = mint, token::authority = job.renter)]
    pub renter_token: Account<'info, TokenAccount>,
    #[account(mut, token::mint = mint, token::authority = job.verifier)]
    pub verifier_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub treasury: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Dismiss<'info> {
    pub admin: Signer<'info>,
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config)]
    pub job: Account<'info, Job>,
}

#[derive(Accounts)]
pub struct Expire<'info> {
    #[account(seeds = [b"config", config.admin.as_ref()], bump = config.bump, has_one = mint, has_one = vault)]
    pub config: Account<'info, Config>,
    #[account(mut, has_one = config, constraint = job.provider == provider.owner @ ExactError::NotYourJob)]
    pub job: Account<'info, Job>,
    #[account(mut, seeds = [b"provider", config.key().as_ref(), provider.owner.as_ref()], bump = provider.bump)]
    pub provider: Account<'info, Provider>,
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, token::mint = mint, token::authority = job.renter)]
    pub renter_token: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

// ------------------------------------------------------------------------- events, errors
#[event]
pub struct Staked {
    pub provider: Pubkey,
    pub amount: u64,
    pub stake: u64,
}

#[event]
pub struct JobOpened {
    pub job: Pubkey,
    pub renter: Pubkey,
    pub provider: Pubkey,
    pub price: u64,
    pub job_digest: [u8; 32],
}

#[event]
pub struct ReceiptCommitted {
    pub job: Pubkey,
    pub commitment: [u8; 32],
}

#[event]
pub struct ReceiptRevealed {
    pub job: Pubkey,
    pub fingerprint: [u8; 32],
    pub trace_root: [u8; 32],
    pub checkpoints: u32,
}

#[event]
pub struct Challenged {
    pub job: Pubkey,
    pub verifier: Pubkey,
    pub fingerprint: [u8; 32],
}

#[event]
pub struct Settled {
    pub job: Pubkey,
    pub provider: Pubkey,
    pub host: u64,
    pub fee: u64,
}

#[event]
pub struct Slashed {
    pub job: Pubkey,
    pub provider: Pubkey,
    pub verifier: Pubkey,
    pub refunded: u64,
    pub to_verifier: u64,
    pub to_tdcc: u64,
    pub divergence_index: u32,
    pub fault_step: u64,
}

#[event]
pub struct Dismissed {
    pub job: Pubkey,
    pub verifier: Pubkey,
}

#[error_code]
pub enum ExactError {
    #[msg("bad parameters")]
    BadParams,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("the stake is locked (no unstake requested, cooldown running, or open jobs)")]
    StakeLocked,
    #[msg("the provider has too little stake or is leaving")]
    ProviderNotStaked,
    #[msg("the job is not in the state this instruction needs")]
    WrongState,
    #[msg("the window for this instruction has closed")]
    WindowClosed,
    #[msg("the window for this instruction is still open")]
    WindowOpen,
    #[msg("the reveal does not open the commitment")]
    BadReveal,
    #[msg("the receipt's model hash is not the job's")]
    ModelMismatch,
    #[msg("the challenge posts the same fingerprint as the receipt")]
    SameFingerprint,
    #[msg("this signer may not act on this job")]
    NotYourJob,
    #[msg("the job was challenged already, and the challenge dismissed")]
    AlreadyChallenged,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_matches_the_shared_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/data/exact_settle_vectors.json"
        ))
        .unwrap();
        let host_bps = v["host_bps"].as_u64().unwrap() as u16;
        let verifier_bps = v["verifier_bps"].as_u64().unwrap() as u16;
        for c in v["accept"].as_array().unwrap() {
            let (h, t) = math::accept(c["price"].as_u64().unwrap(), host_bps);
            assert_eq!(
                (h, t),
                (c["host"].as_u64().unwrap(), c["tdcc"].as_u64().unwrap())
            );
        }
        for c in v["slash"].as_array().unwrap() {
            let (x, t) = math::slash(c["stake"].as_u64().unwrap(), verifier_bps);
            assert_eq!(
                (x, t),
                (c["verifier"].as_u64().unwrap(), c["tdcc"].as_u64().unwrap())
            );
        }
    }

    #[test]
    fn commitment_matches_the_python_vector() {
        // tests/test_exact.py COMMIT_VECTOR
        let got = commitment(
            &[0x11; 32],
            &Pubkey::new_from_array([0x22; 32]),
            &[0x33; 32],
        );
        let want = "00ccd4f49b63c10bc652bb5eab7217fa9a073baa49f8818e68fa47fcb64fa255";
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, want);
    }
}
