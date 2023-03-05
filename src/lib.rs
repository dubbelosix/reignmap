use std::arch::global_asm;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use bincode;
use bs58;

#[derive(Debug,Serialize,Deserialize,Clone)]
enum IndexProof {
    E(usize),
    NE(usize,usize)
}

#[derive(Debug)]
struct SovereignMap<K, V> {
    // prover only
    map: HashMap<K,V>,
    insert_observed_get_count: usize,

    // hints: need to be populated for the zk run
    get_count: usize,
    store_array_snaps: Vec<Vec<(K, V)>>,
    store_array_sort_proofs: Vec<Vec<usize>>,
    access_pattern: Vec<IndexProof>,
    get_count_switch_tracker: Vec<usize>,

    // zk items: need to be 0 for the zk run, but can be used by prover
    original_input_array: Vec<(K,V)>,
    current_get_count: usize,
    store_array_index: usize,

}

impl<K: Eq+Hash+Ord+Clone+Serialize+DeserializeOwned+Debug,
    V:Clone+Serialize+DeserializeOwned+Debug> SovereignMap<K, V> {

    pub fn new() -> SovereignMap<K, V> {
        SovereignMap {
            map: HashMap::new(),
            store_array_snaps: vec![vec![]],
            store_array_sort_proofs: vec![vec![]],
            access_pattern: vec![],
            get_count_switch_tracker: vec![],
            store_array_index: 0,
            insert_observed_get_count: 0,
            get_count: 0,
            original_input_array: vec![],
            current_get_count: 0,


        }
    }

    pub fn get_hints(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.get_count,
            &self.store_array_snaps,
            &self.store_array_sort_proofs,
            &self.access_pattern,
            &self.get_count_switch_tracker
        )).unwrap()
    }

    pub fn set_hints(&mut self, hints: &[u8]) {
        let (get_count,
            store_array_snaps,
            store_array_sort_proofs,
            access_pattern,
            get_count_switch_tracker): (
            usize,
            Vec<Vec<(K, V)>>,
            Vec<Vec<usize>>,
            Vec<IndexProof>,
            Vec<usize>,
        ) = bincode::deserialize(hints).unwrap();
        self.get_count = get_count;
        self.store_array_snaps=store_array_snaps;
        self.store_array_sort_proofs = store_array_sort_proofs;
        self.access_pattern=access_pattern;
        self.get_count_switch_tracker=get_count_switch_tracker;
    }

    #[cfg(feature = "prover")]
    pub fn insert(&mut self, key: K, val: V) {

        // TODO: handle duplicate key insertion. avoiding dups for now

        if self.get_count > self.insert_observed_get_count {
            self.store_array_index+=1;
            self.store_array_snaps.push(self.store_array_snaps[self.store_array_index-1].clone());
            self.insert_observed_get_count = self.get_count;
            self.store_array_sort_proofs.push(vec![]);
            self.get_count_switch_tracker.push(self.get_count);
        }
        self.store_array_snaps[self.store_array_index].push((key.clone(),val.clone()));
        self.store_array_snaps[self.store_array_index].sort_by(|x,y| x.0.cmp(&y.0));
        self.original_input_array.push((key.clone(), val.clone()));
        self.store_array_sort_proofs[self.store_array_index] = vec![];

        for ele in &self.store_array_snaps[self.store_array_index] {
            // TODO: unwrapping on purpose because something is very wrong if an element is not found here
            // crash is preferable. will consider the error case and decide how to handle later
            let idx = self.original_input_array.iter().position(|x| x.0 == ele.0).unwrap();
            self.store_array_sort_proofs[self.store_array_index].push(idx);
        }
        self.map.insert(key,val);

    }

    #[cfg(feature = "prover")]
    pub fn get(&mut self, key: K) -> Option<&V> {
        self.get_count+=1;
        let val = self.map.get(&key);
        let idx = self.bin_search(&key);
        self.access_pattern.push(idx);
        val
    }

    #[cfg(feature = "zk")]
    pub fn insert(&mut self, key: K, val: V) {
        self.original_input_array.push((key, val));
    }

    #[cfg(feature = "zk")]
    pub fn get(&mut self, key: K) -> Option<&V> {
        // TODO: missing a lot of checks here, including sort etc, but will add them later
        self.current_get_count += 1;
        if self.current_get_count > self.get_count {
            panic!("zk gets exceeded hint populated gets");
        }
        if self.current_get_count > self.get_count_switch_tracker[0] {
            self.store_array_index += 1;
            self.get_count_switch_tracker.drain(0..1);
        }
        let sindex = self.access_pattern[self.current_get_count - 1].clone();
        match sindex {
            IndexProof::E(idx) => Some(&self.store_array_snaps[self.store_array_index][idx].1),
            IndexProof::NE(_,_) => None
        }
    }


    pub fn bin_search(&self, target_value: &K) -> IndexProof{
        let mut low = 0usize;
        let mut high = self.store_array_snaps[self.store_array_index].len() - 1;
        let a = &self.store_array_snaps[self.store_array_index];
        let mut mid= 0;
        while low <= high {
            mid = ((high - low) / 2) + low;
            let mid_index = mid as usize;
            let val = &a[mid_index].0;

            if val == target_value {
                return IndexProof::E(mid_index);
            }

            if val < target_value {
                low = mid + 1;
            }

            if val > target_value {
                high = mid - 1;
            }
        }
        IndexProof::NE(mid-1, mid)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "prover")]
    fn map_test() {

        let mut sm: SovereignMap<String,u32> = SovereignMap::new();

        /// SET GET BLOCK
        sm.insert(String::from("rohan"), 10);
        sm.insert(String::from("philippe"), 20);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        sm.insert(String::from("kevin"), 30);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        assert_eq!(*sm.get(String::from("philippe")).unwrap(), 20);
        assert_eq!(sm.get(String::from("plato")), None);
        sm.insert(String::from("plato"), 40);
        assert_eq!(*sm.get(String::from("plato")).unwrap(), 40);
        /// SET GET BLOCK

        println!("{}",bs58::encode(sm.get_hints()).into_string());
    }

    #[test]
    #[cfg(feature = "zk")]
    fn map_test() {

        let mut sm: SovereignMap<String,u32> = SovereignMap::new();
        let hints = bs58::decode("55xRYSyTCScTEPK2SeXnqnQJQzGbYtP1Urq3KM5YkFDignxK7xuCDUy32p3YNP3Akm684xfvRjqbJpdfCpULEntsk5h1x49v3m1hszgowPACJ3BZKrVg3g4SFfbnNP6AnnBK5BL5gMCL9oNaSgirPGRYjBheerSSymA5uzDxa1EQbZWNn7WdSHvgJDBt8pVjcxL5zQb6qsqqZ4b7YnNrSj5rJ42QZNG2fc6gcm6sSYtMFzdAd2br3KkUAq2S6A8sQUhS7kNHEPGKGPAnYKWPWvhmQk4xXkv35DrP1ucDqAvrq3Q7iim4xJsxdbY3sJGG7pinczWBCUVT9GwGZYPpqFmnGHhPRHEzdNtTPCB62xKjU23zsv4n2xusGE4iUpkq5AFQ3R96ziwYzF9q2Eb6jTaf2M5T6QcTF9Hc6dohi4mrwqrWFfcCQczANLqbFPSLr9MQDD33WZkpw2VuqeBubDSLFrMxVSZsLsKBcptUS3TkZGPz1CfnVmjXFZaC4iFARCP3iCw9GGCuvhbw7jPu4Hv3B5TU1wbztwfEbvGrwW1fiBCwrPGHCwZU8M9XoLhrEmbfGmubDa7").into_vec().unwrap();
        sm.set_hints(&hints);
        /// THE PUTS AND GETS NEED TO BE IDENTICAL TO THE ONES ABOVE IN THE PROVER
        /// SET GET BLOCK
        sm.insert(String::from("rohan"), 10);
        sm.insert(String::from("philippe"), 20);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        sm.insert(String::from("kevin"), 30);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        assert_eq!(*sm.get(String::from("rohan")).unwrap(), 10);
        assert_eq!(*sm.get(String::from("philippe")).unwrap(), 20);
        assert_eq!(sm.get(String::from("plato")), None);
        sm.insert(String::from("plato"), 40);
        assert_eq!(*sm.get(String::from("plato")).unwrap(), 40);
        /// SET GET BLOCK

        println!("{:?}",sm);
    }
}
