#[derive(Debug,Clone,PartialEq)]
enum Node {
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>),
    DualNode(Vec<Node>),
    FullNode(Vec<Node>),
    EmptySlot
}

enum Instruction {
    BRANCH(usize),
    HASHER(usize),
    LEAF(usize),
    EXTENSION(usize),
    ADD(usize)
}

fn step(stack: &mut Vec<Node>, keyvals: Vec<(Vec<u8>, Vec<u8>)>, instructions: Vec<Instruction>) -> Node {
    use Instruction::*;
    use Node::*;

    let mut keyvalidx = 0;
    for instr in instructions {
        match instr {
            LEAF(keylength) => {
                let (key, value) = &keyvals[keyvalidx];
                stack.push(Leaf((&key[key.len()-keylength..]).to_vec(), value.to_vec()));
                keyvalidx += 1;
            },
            BRANCH(digit) => {
                if let Some(node) = stack.pop() {
                    let mut children = vec![Node::EmptySlot; 16];
                    children[digit] = node;
                    stack.push(FullNode(children))
                } else {
                    panic!("Could not pop a value from the stack")
                }
            },
            _ => panic!("Unsupported instruction")
        }
    }

    stack.pop().unwrap()
}

#[cfg(test)]
mod tests {
    use super::Instruction::*;
    use super::Node::*;
    use super::*;

    #[test]
    fn tree_with_just_one_leaf() {
        let mut stack = Vec::new();
        let out = step(&mut stack, vec![(vec![1, 2, 3], vec![4,5,6])], vec![LEAF(0)]);
        assert_eq!(out, Leaf(vec![], vec![4,5,6]))
    }

    #[test]
    fn tree_with_one_branch() {
        let mut stack = Vec::new();
        let out = step(&mut stack, vec![(vec![1, 2, 3], vec![4,5,6])], vec![LEAF(0), BRANCH(0)]);
        assert_eq!(out, FullNode(vec![Leaf(vec![], vec![4,5,6]), EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot, EmptySlot]))
    }
}