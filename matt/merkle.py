from typing import List, Iterable, Optional

from .btctools.messages import sha256
from .utils import encode_wit_element, vch2bn

NIL = bytes([0] * 32)


def floor_lg(n: int) -> int:
    """Return floor(log_2(n)) for a positive integer `n`"""

    assert n > 0

    r = 0
    t = 1
    while 2 * t <= n:
        t = 2 * t
        r = r + 1
    return r


def ceil_lg(n: int) -> int:
    """Return ceiling(log_2(n)) for a positive integer `n`."""

    assert n > 0

    r = 0
    t = 1
    while t < n:
        t = 2 * t
        r = r + 1
    return r


def is_power_of_2(n: int) -> bool:
    """For a positive integer `n`, returns `True` is `n` is a perfect power of 2, `False` otherwise."""

    assert n >= 1

    return n & (n - 1) == 0


def largest_power_of_2_less_than(n: int) -> int:
    """For an integer `n` which is at least 2, returns the largest exact power of 2 that is strictly less than `n`."""

    assert n > 1

    if is_power_of_2(n):
        return n // 2
    else:
        return 1 << floor_lg(n)


def element_hash(element_preimage: bytes) -> bytes:
    """Computes the hash of an element to be stored in the Merkle tree."""

    return sha256(element_preimage)


def combine_hashes(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("The elements must be 32-bytes sha256 outputs.")

    return sha256(left + right)


def get_directions(size: int, index: int) -> List[bool]:
    """
    Returns an array of booleans indicating the directions of tree edges in the path from the root to the node with
    the given index in a Merkle tree of the given size.
    """

    assert size > 0
    assert 0 <= index < size

    directions = []
    if size == 1:
        return directions

    while size > 1:
        depth = ceil_lg(size)

        # bitmask of the direction from the current node; also the number of leaves of the left subtree
        mask = 1 << (depth - 1)

        right_child = index & mask != 0
        directions.append(right_child)

        if right_child:
            size -= mask
            index -= mask
        else:
            size = mask
        mask //= 2

    return directions


class MerkleProof:
    """
    This class represents a Merkle proof consisting of a series of hashes the directions to reach
    a certain element from the root, along with the value of the element itself.

    Attributes:
        hashes (list[bytes]): A list of hashes (h_1, ..., h_n), each 32 bytes long.
        directions (list[int]): A list of directions (d_1, ..., d_n), where each direction is either 0 (left) or 1 (right).
        x (bytes): An arbitrary bytes array.
    """

    def __init__(self, hashes: list[bytes], directions: list[bytes], x: bytes):
        """
        Initializes the MerkleProof with given hashes, directions, and an element x.

        Args:
            hashes (list[bytes]): A list of 32-byte long hashes.
            directions (list[int]): A list of directions, each being 0 or 1.
            x (bytes): An arbitrary bytes array.
        """
        if not all(isinstance(h, bytes) and len(h) == 32 for h in hashes):
            raise ValueError("All hashes must be bytes of length 32.")
        if not all(isinstance(d, int) and d in [0, 1] for d in directions):
            raise ValueError("All directions must be either 0 or 1.")
        if not isinstance(x, bytes):
            raise ValueError("x must be of type bytes.")

        self.hashes = hashes
        self.directions = directions
        self.x = x

    def to_wit_stack(self):
        """
        Returns the representation of the Merkle proof for the witness stack, as follows:
            <h_1> <d_1> <h_2> <d_2> ... <h_n> <d_n> <x>
        """
        return [encode_wit_element(t) for pair in zip(self.hashes, self.directions) for t in pair] + [self.x]

    def from_wit_stack(wit_stack: list[bytes]):
        """
        Constructs a MerkleProof instance from a given witness stack.
        
        Args:
            wit_stack (list): A list of hashes and directions followed by an element x, structured as
                            [<h_1>, <d_1>, <h_2>, <d_2>, ..., <h_n>, <d_n>, <x>]
        Returns:
            MerkleProof: An instance of the MerkleProof class.
        """
        if len(wit_stack) < 3 or len(wit_stack) % 2 == 0:
            raise ValueError("Witness stack must contain an odd number of elements and at least 3 elements.")

        *hash_dir_pairs, x = wit_stack
        hashes, directions = hash_dir_pairs[::2], hash_dir_pairs[1::2]
        directions = [vch2bn(d) for d in directions]

        return MerkleProof(hashes, directions, x)

    def __repr__(self) -> str:
        """
        Returns a string representation of the MerkleProof object.
        """
        return f"MerkleProof(hashes={self.hashes}, directions={self.directions}, element={self.x})"

    def __str__(self) -> str:
        """
        Returns a readable string representation of the MerkleProof object.
        """
        return f"MerkleProof(hashes=[{', '.join(map(lambda t: t.hex(), self.hashes))}], directions={self.directions}, element={self.x.hex()})"


# root is the only node with parent == None
# leaves have left == right == None
class Node:
    def __init__(self, left: Optional['Node'], right: Optional['Node'], parent: 'Node', value: bytes):
        self.left = left
        self.right = right
        self.parent = parent
        self.value = value

    def recompute_value(self) -> bytes:
        assert self.left is not None
        assert self.right is not None
        self.value = combine_hashes(self.left.value, self.right.value)

    def sibling(self) -> 'Node':
        if self.parent is None:
            raise IndexError("The root does not have a sibling.")

        if self.parent.left == self:
            return self.parent.right
        elif self.parent.right == self:
            return self.parent.left
        else:
            raise IndexError("Invalid state: not a child of his parent.")


def make_tree(leaves: List[Node], begin: int, size: int) -> Node:
    """Given a list of nodes, builds the left-complete Merkle tree on top of it.
    The nodes in `leaves` are modified by setting their `parent` field appropriately.
    It returns the root of the newly built tree.
    """

    if size == 0:
        return []
    if size == 1:
        return leaves[begin]

    lchild_size = largest_power_of_2_less_than(size)

    lchild = make_tree(leaves, begin, lchild_size)
    rchild = make_tree(leaves, begin + lchild_size, size - lchild_size)
    root = Node(lchild, rchild, None, None)
    root.recompute_value()
    lchild.parent = rchild.parent = root
    return root


class MerkleTree:
    """
    Maintains a dynamic vector of values and the Merkle tree built on top of it. The elements of the vector are stored
    as the leaves of a binary tree. It is possible to achange an existing element, but the size of the tree is fixed;
    the hashes in the Merkle tree will be recomputed after each operation in O(log n) time, for a vector with n
    elements.
    The value of each internal node is the hash of the concatenation of:
    - the value of the left child;
    - the value of the right child.

    The binary tree has the following properties (assuming the vector contains n leaves):
    - There are always n - 1 internal nodes; all the internal nodes have exactly two children.
    - If a subtree has n > 1 leaves, then the left subchild is a complete subtree with p leaves, where p is the largest
      power of 2 smaller than n.
    """

    def __init__(self, elements: Iterable[bytes] = []):
        self.leaves = [Node(None, None, None, el) for el in elements]
        n_elements = len(self.leaves)
        if n_elements > 0:
            self.root_node = make_tree(self.leaves, 0, n_elements)
            self.depth = ceil_lg(n_elements)
        else:
            self.root_node = None
            self.depth = None

    def __len__(self) -> int:
        """Return the total number of leaves in the tree."""
        return len(self.leaves)

    @property
    def root(self) -> bytes:
        """Return the Merkle root, or None if the tree is empty."""
        return NIL if self.root_node is None else self.root_node.value

    def copy(self):
        """Return an identical copy of this Merkle tree."""
        return MerkleTree([leaf.value for leaf in self.leaves])

    def set(self, index: int, x: bytes) -> None:
        """
        Set the value of the leaf at position `index` to `x`, recomputing the tree accordingly.
        If `index` equals the current number of leaves, then it is equivalent to `add(x)`.

        Cost: Worst case O(log n).
        """
        if not (0 <= index < len(self.leaves)):
            raise ValueError("Leaf index out of bounds")

        if len(x) != 32:
            raise ValueError("Inserted elements must be exactly 32 bytes long.")

        if index == len(self.leaves):
            self.add(x)
        else:
            self.leaves[index].value = x
            self.fix_up(self.leaves[index].parent)

    def fix_up(self, node: Node):
        while node is not None:
            node.recompute_value()
            node = node.parent

    def get(self, i: int) -> bytes:
        """Return the value of the leaf with index `i`, where 0 <= i < len(self)."""
        return self.leaves[i].value

    def leaf_index(self, x: bytes) -> int:
        """Return the index of the leaf with hash `x`. Raises `ValueError` if not found."""
        idx = 0
        while idx < len(self):
            if self.leaves[idx].value == x:
                return idx
            idx += 1
        raise ValueError("Leaf not found")

    def prove_leaf(self, index: int) -> List[bytes]:
        """Produce the Merkle proof of membership for the leaf with the given index where 0 <= index < len(self)."""
        node = self.leaves[index]
        proof = []
        x = node.value
        while node.parent is not None:
            sibling = node.sibling()
            assert sibling is not None

            proof.append(sibling.value)

            node = node.parent

        return MerkleProof(list(reversed(proof)), get_directions(len(self), index), x)
