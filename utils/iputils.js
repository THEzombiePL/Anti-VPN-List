/**
 * Converts an IPv4 address string to a 32-bit number.
 * Example: "127.0.0.1" => 2130706433
 * @param {string} ip - IPv4 address.
 * @returns {number} 32-bit integer representation.
 */
export function ipToNumber(ip) {
	return ip
		.split(".")
		.reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
}

/**
 * Converts a CIDR string to a numeric IP range [start, end].
 * @param {string} cidr - CIDR notation (e.g. "192.168.0.0/16").
 * @returns {[number, number]} Tuple with start and end IP as numbers.
 */
export function cidrToRange(cidr) {
	const [ip, prefix] = cidr.split("/");
	const ipNum = ipToNumber(ip);
	const maskBits = 32 - Number(prefix);
	const numAddresses = 2 ** maskBits;
	const start = ipNum & ~(numAddresses - 1);
	const end = start + numAddresses - 1;
	return [start, end];
}

/**
 * Converts a CIDR to a binary prefix string.
 * Example: "192.168.0.0/16" => "1100000010101000"
 * @param {string} cidr - CIDR notation.
 * @returns {string} Binary prefix string.
 */
export function cidrToBinaryPrefix(cidr) {
	const [ip, mask] = cidr.split("/");
	return ipToBinary(ip).slice(0, parseInt(mask));
}

/**
 * Converts an IPv4 address to a 32-bit binary string.
 * Example: "127.0.0.1" => "01111111000000000000000000000001"
 * @param {string} ip - IPv4 address.
 * @returns {string} 32-bit binary string.
 */
export function ipToBinary(ip) {
	return ip
		.split(".")
		.map((octet) => parseInt(octet, 10).toString(2).padStart(8, "0"))
		.join("");
}
