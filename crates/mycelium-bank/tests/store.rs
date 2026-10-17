use mycelium_bank::store::BankStore;
use mycelium_bank::assets::Asset;
use tempfile::tempdir;

#[test]
fn bank_store_persists_accounts() {
    let dir = tempdir().unwrap();
    {
        let mut bank = BankStore::open(dir.path()).unwrap();
        bank.open_account("acc-1", "owner", 10).unwrap();
        bank.credit("acc-1", "USDC", 500, "r1", 11).unwrap();
        assert_eq!(bank.account("acc-1").unwrap().balance(Asset::Usdc), 500);
    }
    let bank = BankStore::open(dir.path()).unwrap();
    assert_eq!(bank.account("acc-1").unwrap().balance(Asset::Usdc), 500);
    let ledger = bank.ledger.read_all().unwrap();
    assert_eq!(ledger.len(), 1);
}
