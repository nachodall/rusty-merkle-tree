use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq)]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: [u8; 32],
    leaves: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pairs: Vec<([u8; 32], Side)>,
}

impl MerkleTree {
    pub fn new(array: Vec<&str>) -> Result<Self, String> {
        if array.is_empty() {
            return Err("You can't create an empty Merkle Tree".to_string());
        }

        let mut leaves = Vec::with_capacity(array.len());
        for element in array {
            let leaf = Self::hash_bytes(element.as_bytes());
            leaves.push(leaf);
        }

        let root = Self::calculate_merkle_root(&leaves);

        Ok(MerkleTree { root, leaves })
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn leaves_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn leaf_at(&self, idx: usize) -> [u8; 32] {
        self.leaves[idx]
    }

    pub fn add_leaf(&mut self, element: &str) {
        let new_hash = Self::hash_bytes(element.as_bytes());
        self.leaves.push(new_hash);
        self.root = Self::calculate_merkle_root(&self.leaves);
    }

    pub fn formulate_proof_of_inclusion(&self, data: &str) -> Option<MerkleProof> {
        let leaf_hash = Self::hash_bytes(data.as_bytes());
        let index = self.leaves.iter().position(|h| h == &leaf_hash)?;

        let mut elements_of_proof = Vec::new();
        Self::formulate_proof_recursive(&self.leaves, index, &mut elements_of_proof);

        Some(MerkleProof {
            pairs: elements_of_proof,
        })
    }

    fn formulate_proof_recursive(
        current_level: &[[u8; 32]],
        index: usize,
        elements_of_proof: &mut Vec<([u8; 32], Side)>,
    ) {
        if current_level.len() <= 1 {
            return;
        }

        let is_even_index = index % 2 == 0;
        let pair_idx = if is_even_index {
            if index + 1 == current_level.len() {
                index
            } else {
                index + 1
            }
        } else {
            index - 1
        };

        let side = if is_even_index {
            Side::Right
        } else {
            Side::Left
        };

        elements_of_proof.push((current_level[pair_idx], side));

        Self::formulate_proof_recursive(
            &Self::calculate_next_level_of_tree(current_level),
            index / 2,
            elements_of_proof,
        );
    }

    fn calculate_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves {
            [] => unreachable!("Empty leaves in calculate_merkle_root"),
            [single] => *single,
            _ => {
                let next_level_of_tree = Self::calculate_next_level_of_tree(leaves);
                Self::calculate_merkle_root(&next_level_of_tree)
            }
        }
    }

    fn calculate_next_level_of_tree(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut next_level_of_tree = Vec::with_capacity((leaves.len() + 1) / 2);

        for pair in leaves.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };

            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);
            next_level_of_tree.push(Self::hash_bytes(&combined));
        }

        next_level_of_tree
    }

    pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn root_hex(&self) -> String {
        self.root.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl MerkleProof {
    pub fn verify(&self, root: [u8; 32], leaf: &str) -> bool {
        let mut current_hash = MerkleTree::hash_bytes(leaf.as_bytes());

        for (sibling_hash, side) in &self.pairs {
            let mut combined = [0u8; 64];
            match side {
                Side::Left => {
                    combined[..32].copy_from_slice(sibling_hash);
                    combined[32..].copy_from_slice(&current_hash);
                }
                Side::Right => {
                    combined[..32].copy_from_slice(&current_hash);
                    combined[32..].copy_from_slice(sibling_hash);
                }
            };
            current_hash = MerkleTree::hash_bytes(&combined);
        }

        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[test]
    fn test_merkle_tree_can_be_created_from_a_non_empty_array() {
        let data = vec!["hola", "mundo", "lambda", "class"];
        let tree = MerkleTree::new(data).expect("Failed to initialize MerkleTree with valid data");

        assert_eq!(
            tree.leaves_count(),
            4,
            "Leaf count mismatch: expected 4 leaves to be initialized"
        );
    }

    #[test]
    fn test_merkle_tree_cant_be_created_from_an_empty_array() {
        let data: Vec<&str> = vec![];
        let tree_result = MerkleTree::new(data);

        assert!(
            tree_result.is_err(),
            "MerkleTree should return an Error when created with an empty array"
        );
    }

    #[test]
    fn test_merkle_tree_nodes_are_hashed() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]).unwrap();
        let expected_hash_for_idx_0 =
            hex_to_bytes("b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79");

        assert_eq!(
            tree.leaf_at(0),
            expected_hash_for_idx_0,
            "The leaf hash at index 0 does not match the expected SHA-256 output"
        );
    }

    #[test]
    fn test_merkle_root_of_a_tree_of_one_leaf() {
        let tree = MerkleTree::new(vec!["hola"]).unwrap();
        let expected_hash_for_root =
            "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79";

        assert_eq!(
            tree.root_hex(),
            expected_hash_for_root,
            "Root hash mismatch for a single-leaf tree"
        );
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_two_leaves() {
        let tree = MerkleTree::new(vec!["hola", "mundo"]).unwrap();
        let expected_root = "c030ed83e4b337813e905c456a45c002790bc315b88ec9d47962b8563d502803";

        assert_eq!(
            tree.root_hex(),
            expected_root,
            "Root hash mismatch for a two-leaf tree"
        );
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_three_leaves() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda"]).unwrap();
        let expected_root = "04a9df5a1a37270eefcd5f9529d959ea89d0dd325d0787cbba98b99afa90ce60";

        assert_eq!(
            tree.root_hex(),
            expected_root,
            "Root hash mismatch for a three-leaf (unbalanced) tree"
        );
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_four_leaves() {
        let data = vec!["rust", "ethereum", "merkle", "tree"];
        let tree = MerkleTree::new(data).unwrap();
        let expected_root = "904b4c3045552d5c1dd343072c64b5d59fde0b8c015aec2f96abf9cb61c6d506";

        assert_eq!(
            tree.root_hex(),
            expected_root,
            "Root hash mismatch for a four-leaf (balanced) tree"
        );
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_five_leaves() {
        let data = vec!["hola", "mundo", "lambda", "class", "rust"];
        let tree = MerkleTree::new(data).unwrap();
        let expected_root = "d2311a51d8b51ffe570992fb96726f0250c90b4e2fc4d37cee937cc4f253ca12";

        assert_eq!(
            tree.root_hex(),
            expected_root,
            "Root hash mismatch for a five-leaf tree"
        );
    }

    #[test]
    fn test_verify_valid_proof() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]).unwrap();
        let root = tree.root();
        let leaf_to_prove = "lambda";

        let proof = tree
            .formulate_proof_of_inclusion(leaf_to_prove)
            .expect("Expected a valid proof to be generated for an existing leaf");

        assert!(
            proof.verify(root, leaf_to_prove),
            "Verification failed for a valid proof and leaf combination"
        );
    }

    #[test]
    fn test_proof_for_non_existent_leaf_fails() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]).unwrap();
        let non_existent_leaf = "rust";

        let proof = tree.formulate_proof_of_inclusion(non_existent_leaf);

        assert!(
            proof.is_none(),
            "A proof should not be generated (must be None) for a leaf that is not in the tree"
        );
    }

    #[test]
    fn test_verify_altered_proof_fails() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]).unwrap();
        let root = tree.root();
        let leaf_to_prove = "lambda";

        let mut proof = tree
            .formulate_proof_of_inclusion(leaf_to_prove)
            .expect("Expected proof generation to succeed");

        proof.pairs[0].0[0] ^= 0xFF;

        assert!(
            !proof.verify(root, leaf_to_prove),
            "An altered proof must fail the verification process"
        );
    }

    #[test]
    fn test_verify_all_leaves_in_larger_tree_exhaustively() {
        let data = vec![
            "rust",
            "haskell",
            "c++",
            "python",
            "smalltalk",
            "java",
            "assembly",
            "javascript",
            "go",
            "lua",
            "lisp",
            "c",
            "c#",
            "fortran",
            "elixir",
            "zig",
            "ruby",
            "pascal",
            "prolog",
        ];

        let tree = MerkleTree::new(data.clone()).unwrap();
        let root = tree.root();

        for leaf in data {
            let proof_wrapper = tree.formulate_proof_of_inclusion(leaf);

            assert!(
                proof_wrapper.is_some(),
                "Proof generation failed unexpectedly for existing leaf: {}",
                leaf
            );

            let proof = proof_wrapper.unwrap();
            assert!(
                proof.verify(root, leaf),
                "Cryptographic verification failed for valid leaf: {}",
                leaf
            );
        }
    }

    #[test]
    fn test_dynamic_tree_add_leaf_mutates_root_and_count() {
        let mut tree = MerkleTree::new(vec!["A", "B"]).unwrap();
        let initial_root = tree.root();

        tree.add_leaf("C");

        assert_eq!(
            tree.leaves_count(),
            3,
            "Leaf count should increment to 3 after adding one element"
        );

        assert_ne!(
            initial_root,
            tree.root(),
            "The Merkle root must mutate after a new leaf is dynamically added"
        );
    }

    #[test]
    fn test_dynamic_tree_can_verify_old_and_new_leaves() {
        let mut tree = MerkleTree::new(vec!["rust", "haskell"]).unwrap();
        tree.add_leaf("c++");
        let current_root = tree.root();

        let proof_old = tree
            .formulate_proof_of_inclusion("rust")
            .expect("Failed to generate proof for an old node after mutation");

        assert!(
            proof_old.verify(current_root, "rust"),
            "Failed to verify a pre-existing node against the updated dynamic root"
        );

        let proof_new = tree
            .formulate_proof_of_inclusion("c++")
            .expect("Failed to generate proof for the newly added node");

        assert!(
            proof_new.verify(current_root, "c++"),
            "Failed to verify the newly appended node against the updated dynamic root"
        );
    }

    #[test]
    fn test_dynamic_tree_invalidates_old_proofs() {
        let mut tree = MerkleTree::new(vec!["A", "B"]).unwrap();

        let old_proof_for_a = tree
            .formulate_proof_of_inclusion("A")
            .expect("Initial proof generation failed");

        tree.add_leaf("C");
        let new_root = tree.root();

        assert!(
            !old_proof_for_a.verify(new_root, "A"),
            "Security vulnerability: An old proof should be strictly invalid against a mutated root"
        );
    }

    #[test]
    fn test_dynamic_tree_multiple_additions_maintain_integrity() {
        let mut tree = MerkleTree::new(vec!["inicio"]).unwrap();

        tree.add_leaf("medio_1");
        tree.add_leaf("medio_2");
        tree.add_leaf("fin");

        assert_eq!(
            tree.leaves_count(),
            4,
            "Tree did not process multiple dynamic additions correctly"
        );

        let root = tree.root();

        for leaf in ["inicio", "medio_1", "medio_2", "fin"] {
            let proof = tree
                .formulate_proof_of_inclusion(leaf)
                .expect(&format!("Proof generation failed for leaf: {}", leaf));

            assert!(
                proof.verify(root, leaf),
                "Verification failed for leaf '{}' in a dynamically built tree",
                leaf
            );
        }
    }
}
