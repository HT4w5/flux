package trie

type node[T any] struct {
	children [256]int // 0 -> empty
	valueIdx int      // 0 -> empty
}

// --- PrefixTrie ---

type PrefixTrie[T any] struct {
	nodes  []node[T]
	values []T
}

type PrefixTrieBuilder[T any] PrefixTrie[T]

func (tb *PrefixTrieBuilder[T]) Add(prefix string, value T) {
	cur := 0
	// Find node (create if not exist)
	for i := range len(prefix) {
		b := prefix[i]
		next := tb.nodes[cur].children[b]
		if next == 0 {
			// Create new node
			tb.nodes = append(tb.nodes, node[T]{})
			next = len(tb.nodes) - 1
			tb.nodes[cur].children[b] = next
		}
		cur = next
	}

	// Store value
	old := tb.nodes[cur].valueIdx
	if old != 0 {
		tb.values[old-1] = value // Overwrite
	} else {
		tb.values = append(tb.values, value)
		tb.nodes[cur].valueIdx = len(tb.values)
	}
}

func (tb PrefixTrieBuilder[T]) Build() PrefixTrie[T] {
	return PrefixTrie[T](tb)
}

func (trie PrefixTrie[T]) PreciseMatch(s string) (value T, ok bool) {
	if len(trie.nodes) == 0 {
		return
	}
	cur := 0
	for i := range len(s) {
		next := trie.nodes[cur].children[s[i]]
		if next == 0 {
			return
		}
		cur = next
	}
	idx := trie.nodes[cur].valueIdx
	if idx == 0 {
		return
	}
	return trie.values[idx-1], true
}

func (trie PrefixTrie[T]) LongestPrefixMatch(s string) (value T, ok bool) {
	if len(trie.nodes) == 0 {
		return
	}
	cur := 0
	bestValueIdx := 0
	if trie.nodes[0].valueIdx != 0 {
		bestValueIdx = trie.nodes[0].valueIdx
	}
	for i := range len(s) {
		next := trie.nodes[cur].children[s[i]]
		if next == 0 {
			break
		}
		cur = next
		if idx := trie.nodes[cur].valueIdx; idx != 0 {
			bestValueIdx = idx
		}
	}
	if bestValueIdx == 0 {
		return
	}
	return trie.values[bestValueIdx-1], true
}
