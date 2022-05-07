package batchedsmt

import (
	"bytes"
)

// update adds a sorted list of keys and their values to the trie.
// It returns the root of the updated tree.
func (smt *SMT) update(root []byte, keys, values, batch [][]byte, iBatch, height int, shortcut, store bool, resultChan chan<- (updateResult)) {
	// when we reach the bot of the whole tree
	if height == 0 {
		if bytes.Equal(values[0], DefaultLeaf) {
			resultChan <- updateResult{nil, nil}
		} else {
			resultChan <- updateResult{values[0], nil}
		}
		return
	}

	// load the batch, left node, and right node
	batch, iBatch, lnode, rnode, isShortcut, err := smt.loadChildren(root, height, iBatch, batch)
	if err != nil {
		resultChan <- updateResult{nil, err}
		return
	}

	if isShortcut {
		keys, values = addShortcutToKV(keys, values, lnode[:HashLength], rnode[:HashLength])
		// The shortcut node was added to keys and values so consider this subtree default.
		lnode, rnode = nil, nil
		// update in the batch (set key, value to default to the next loadChildren is correct)
		batch[2*iBatch+1] = nil
		batch[2*iBatch+2] = nil
	}

	// Split the keys array so each branch can be updated in parallel
	lkeys, rkeys := splitKeys(keys, TreeHeight-height)
	splitIndex := len(lkeys)
	lvalues, rvalues := values[:splitIndex], values[splitIndex:]

	if shortcut {
		store = false    //stop storing only after the shortcut node.
		shortcut = false // remove shortcut node flag
	}

	if (len(lnode) == 0) && (len(rnode) == 0) && (len(keys) == 1) && store {
		if !bytes.Equal(values[0], DefaultLeaf) {
			shortcut = true
		} else {
			// if the subtree contains only one key, store the key/value in a shortcut node
			store = false
		}
	}

	switch {
	case len(lkeys) == 0 && len(rkeys) > 0:
		smt.updateRight(lnode, rnode, root, keys, values, batch, iBatch, height, shortcut, store, resultChan)
	case len(lkeys) > 0 && len(rkeys) == 0:
		smt.updateLeft(lnode, rnode, root, keys, values, batch, iBatch, height, shortcut, store, resultChan)
	default:
		smt.updateParallel(lnode, rnode, root, keys, values, batch, lkeys, rkeys, lvalues, rvalues, iBatch, height, shortcut, store, resultChan)
	}
}

// updateParallel updates both sides of the trie simultaneously
func (smt *SMT) updateParallel(lnode, rnode, root []byte, keys, values, batch, lkeys, rkeys, lvalues, rvalues [][]byte, iBatch, height int, shortcut, store bool, resultChan chan<- (updateResult)) {
	// keys are separated between the left and right branches
	// update the branches in parallel
	leftResultChan := make(chan updateResult, 1)
	rightResultChan := make(chan updateResult, 1)
	go smt.update(lnode, lkeys, lvalues, batch, 2*iBatch+1, height-1, shortcut, store, leftResultChan)
	go smt.update(rnode, rkeys, rvalues, batch, 2*iBatch+2, height-1, shortcut, store, rightResultChan)
	leftResult := <-leftResultChan
	rightResult := <-rightResultChan
	close(leftResultChan)
	close(rightResultChan)
	if leftResult.err != nil {
		resultChan <- updateResult{nil, leftResult.err}
		return
	}
	if rightResult.err != nil {
		resultChan <- updateResult{nil, rightResult.err}
		return
	}
	resultChan <- updateResult{smt.interiorHash(leftResult.update, rightResult.update, height, iBatch, root, shortcut, store, keys, values, batch), nil}
}

// updateRight updates the right side of the tree
func (smt *SMT) updateRight(lnode, rnode, root []byte, keys, values, batch [][]byte, iBatch, height int, shortcut, store bool, ch chan<- (updateResult)) {
	// all the keys go in the right subtree
	newch := make(chan updateResult, 1)
	smt.update(rnode, keys, values, batch, 2*iBatch+2, height-1, shortcut, store, newch)
	res := <-newch
	close(newch)
	if res.err != nil {
		ch <- updateResult{nil, res.err}
		return
	}
	ch <- updateResult{smt.interiorHash(lnode, res.update, height, iBatch, root, shortcut, store, keys, values, batch), nil}
}

// updateLeft updates the left side of the tree
func (smt *SMT) updateLeft(lnode, rnode, root []byte, keys, values, batch [][]byte, iBatch, height int, shortcut, store bool, ch chan<- (updateResult)) {
	// all the keys go in the left subtree
	newch := make(chan updateResult, 1)
	smt.update(lnode, keys, values, batch, 2*iBatch+1, height-1, shortcut, store, newch)
	res := <-newch
	close(newch)
	if res.err != nil {
		ch <- updateResult{nil, res.err}
		return
	}
	ch <- updateResult{smt.interiorHash(res.update, rnode, height, iBatch, root, shortcut, store, keys, values, batch), nil}
}
