use std::arch::global_asm;
use std::collections::HashMap;
use std::hash::Hash;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use bincode;

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

impl<K: Eq+Hash+Ord+Clone+Serialize+DeserializeOwned, V:Clone+Serialize+DeserializeOwned> SovereignMap<K, V> {

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
        self.current_get_count += 1;
        if self.current_get_count > self.get_count {
            panic!("zk gets exceeded hint populated gets");
        }
        if self.current_get_count > self.get_count_switch_tracker[0] {
            self.store_array_index += 1
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
    fn map_test() {
        let mut sm: SovereignMap<String,u32> = SovereignMap::new();
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

        println!("{:?}",sm);
    }
}
