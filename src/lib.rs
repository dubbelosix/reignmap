use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug)]
enum IndexProof {
    E(usize),
    NE(usize,usize)
}

#[derive(Debug)]
struct SovereignMap<K, V> {
    // prover only
    map: HashMap<K,V>,
    store_array_index: usize,
    insert_observed_get_count: usize,
    get_count: usize,

    // hints: need to be populated for the zk run
    store_array_snaps: Vec<Vec<(K, V)>>,
    store_array_sort_proofs: Vec<Vec<usize>>,
    access_pattern: Vec<IndexProof>,

    // zk items: need to be 0 for the zk run, but can be used by prover
    original_input_array: Vec<(K,V)>,

}

impl<K: Eq+Hash+Ord+Clone, V:Clone> SovereignMap<K, V> {

    pub fn new() -> SovereignMap<K, V> {
        SovereignMap {
            map: HashMap::new(),
            store_array_snaps: vec![vec![]],
            store_array_sort_proofs: vec![],
            access_pattern: vec![],
            store_array_index: 0,
            insert_observed_get_count: 0,
            get_count: 0,
            original_input_array: vec![]

        }
    }

    #[cfg(feature = "prover")]
    pub fn insert(&mut self, key: K, val: V) {

        // TODO: handle duplicate key insertion. avoiding dups for now

        if self.get_count > self.insert_observed_get_count {
            self.store_array_index+=1;
            self.store_array_snaps.push(self.store_array_snaps[self.store_array_index-1].clone());
            self.insert_observed_get_count = self.get_count
        }
        self.store_array_snaps[self.store_array_index].push((key.clone(),val.clone()));
        self.store_array_snaps[self.store_array_index].sort_by(|x,y| x.0.cmp(&y.0));
        original_input_array.push((key.clone(), val.clone()));
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
        IndexProof::NE(mid as usize, mid+1)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_test() {
        let mut sm: SovereignMap<&str,u32> = SovereignMap::new();
        sm.insert("rohan", 10);
        sm.insert("philippe", 20);
        assert_eq!(*sm.get("rohan").unwrap(), 10);
        sm.insert("kevin", 30);
        assert_eq!(*sm.get("rohan").unwrap(), 10);
        assert_eq!(*sm.get("rohan").unwrap(), 10);
        assert_eq!(*sm.get("rohan").unwrap(), 10);
        assert_eq!(*sm.get("philippe").unwrap(), 20);
        assert_eq!(sm.get("plato"), None);
        sm.insert("plato", 40);
        assert_eq!(*sm.get("plato").unwrap(), 40);

        println!("{:?}",sm);
    }
}
