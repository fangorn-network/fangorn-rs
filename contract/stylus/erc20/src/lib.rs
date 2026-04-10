#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(feature = "contract-client-gen", allow(unused_imports))]
extern crate alloc;

use alloc::vec::Vec;
use stylus_sdk::alloy_primitives::{Address, U256};
use stylus_sdk::alloy_sol_types::sol;
use stylus_sdk::prelude::*;

// ──────────────────────────────────────────────
// Events & Errors (Solidity ABI-compatible)
// ──────────────────────────────────────────────
sol! {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error InsufficientBalance(address from, uint256 have, uint256 want);
    error InsufficientAllowance(address spender, uint256 have, uint256 want);
    error ZeroAddress();
}

// ──────────────────────────────────────────────
// Storage
// ──────────────────────────────────────────────
sol_storage! {
    #[entrypoint]
    pub struct ERC20 {
        mapping(address => uint256) balances;
        mapping(address => mapping(address => uint256)) allowances;
        uint256 total_supply;
    }
}

// ──────────────────────────────────────────────
// ERC-20 public interface + open mint
// ──────────────────────────────────────────────
#[public]
impl ERC20 {
    // ── ERC-20 views ─────────────────────────

    /// Returns the total token supply.
    pub fn total_supply(&self) -> U256 {
        self.total_supply.get()
    }

    /// Returns the balance of `account`.
    pub fn balance_of(&self, account: Address) -> U256 {
        self.balances.get(account)
    }

    /// Returns the remaining allowance `spender` can spend on behalf of `owner`.
    pub fn allowance(&self, owner: Address, spender: Address) -> U256 {
        self.allowances.getter(owner).get(spender)
    }

    // ── ERC-20 mutations ─────────────────────

    /// Transfers `value` tokens from the caller to `to`.
    pub fn transfer(&mut self, to: Address, value: U256) -> Result<bool, Vec<u8>> {
        let from = self.vm().msg_sender();
        self._transfer(from, to, value)?;
        Ok(true)
    }

    /// Approves `spender` to spend `value` tokens on behalf of the caller.
    pub fn approve(&mut self, spender: Address, value: U256) -> Result<bool, Vec<u8>> {
        let owner = self.vm().msg_sender();
        self._approve(owner, spender, value)?;
        Ok(true)
    }

    /// Transfers `value` tokens from `from` to `to`, deducting from the caller's allowance.
    pub fn transfer_from(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
    ) -> Result<bool, Vec<u8>> {
        let spender = self.vm().msg_sender();
        self._spend_allowance(from, spender, value)?;
        self._transfer(from, to, value)?;
        Ok(true)
    }

    // ── Mintable (open, mirrors the ink! PSP22Mintable default) ──

    /// Mints `amount` new tokens to `to`.
    /// Anyone can call this — same as the PSP22Mintable default impl.
    pub fn mint(&mut self, to: Address, amount: U256) -> Result<(), Vec<u8>> {
        self._mint_to(to, amount)
    }
}

// ──────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────
impl ERC20 {
    fn _transfer(&mut self, from: Address, to: Address, value: U256) -> Result<(), Vec<u8>> {
        if to == Address::ZERO {
            return Err(b"ZeroAddress".to_vec());
        }

        let from_balance = self.balances.get(from);
        if from_balance < value {
            return Err(b"InsufficientBalance".to_vec());
        }

        self.balances.setter(from).set(from_balance - value);
        let to_balance = self.balances.get(to);
        self.balances.setter(to).set(to_balance + value);

        self.vm().log(Transfer { from, to, value });

        Ok(())
    }

    fn _approve(
        &mut self,
        owner: Address,
        spender: Address,
        value: U256,
    ) -> Result<(), Vec<u8>> {
        if spender == Address::ZERO {
            return Err(b"ZeroAddress".to_vec());
        }

        self.allowances.setter(owner).setter(spender).set(value);

        self.vm().log(Approval {
            owner,
            spender,
            value,
        });

        Ok(())
    }

    fn _spend_allowance(
        &mut self,
        owner: Address,
        spender: Address,
        value: U256,
    ) -> Result<(), Vec<u8>> {
        let current = self.allowances.getter(owner).get(spender);
        // U256::MAX acts as "unlimited" allowance (same convention as ERC-20)
        if current != U256::MAX {
            if current < value {
                return Err(b"InsufficientAllowance".to_vec());
            }
            self.allowances
                .setter(owner)
                .setter(spender)
                .set(current - value);
        }
        Ok(())
    }

    fn _mint_to(&mut self, to: Address, amount: U256) -> Result<(), Vec<u8>> {
        if to == Address::ZERO {
            return Err(b"ZeroAddress".to_vec());
        }

        let supply = self.total_supply.get();
        self.total_supply.set(supply + amount);

        let balance = self.balances.get(to);
        self.balances.setter(to).set(balance + amount);

        self.vm().log(Transfer {
            from: Address::ZERO,
            to,
            value: amount,
        });

        Ok(())
    }
}