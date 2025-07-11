/**
 * Node of a Radix Tree (Prefix Tree) for binary prefixes.
 */
export class RadixNode {
	/**
	 * @param {string} value - The prefix value for this node.
	 */
	constructor(value = "") {
		this.value = value;
		this.children = new Map();
		this.isEnd = false;
	}
}

/**
 * Radix Tree (Prefix Tree) for efficient prefix containment checks.
 */
export class RadixTree {
	constructor() {
		this.root = new RadixNode();
	}

	/**
	 * Inserts a binary prefix into the tree.
	 * @param {string} prefix - Binary prefix string (e.g. "11000000").
	 */
	insert(prefix) {
		let node = this.root;
		while (prefix.length > 0) {
			let found = false;

			for (const [key, child] of node.children.entries()) {
				let commonPrefixLength = this._commonPrefixLength(prefix, key);
				if (commonPrefixLength > 0) {
					const commonPrefix = prefix.slice(0, commonPrefixLength);
					const remainingPrefix = prefix.slice(commonPrefixLength);
					const remainingKey = key.slice(commonPrefixLength);

					if (remainingKey.length > 0) {
						const newChild = new RadixNode(remainingKey);
						newChild.children = child.children;
						newChild.isEnd = child.isEnd;

						child.value = commonPrefix;
						child.children = new Map([[remainingKey, newChild]]);
						child.isEnd = false;
					}

					prefix = remainingPrefix;
					node = child;
					found = true;
					break;
				}
			}

			if (!found) {
				const newNode = new RadixNode(prefix);
				newNode.isEnd = true;
				node.children.set(prefix, newNode);
				return;
			}
		}

		node.isEnd = true;
	}

	/**
	 * Checks if a binary string is contained in the tree (any prefix matches).
	 * @param {string} binaryIP - Binary string to check (e.g. IP as binary).
	 * @returns {boolean} True if contained, false otherwise.
	 */
	search(binaryIP) {
		let node = this.root;
		while (binaryIP.length > 0) {
			let found = false;
			for (const [key, child] of node.children.entries()) {
				if (binaryIP.startsWith(key)) {
					binaryIP = binaryIP.slice(key.length);
					node = child;
					found = true;
					if (child.isEnd) return true;
					break;
				}
			}
			if (!found) break;
		}
		return node.isEnd;
	}

	/**
	 * Returns the length of the common prefix between two strings.
	 * @param {string} str1
	 * @param {string} str2
	 * @returns {number} Length of common prefix.
	 */
	_commonPrefixLength(str1, str2) {
		let i = 0;
		while (i < str1.length && i < str2.length && str1[i] === str2[i]) {
			i++;
		}
		return i;
	}
}

export default { RadixNode, RadixTree };
