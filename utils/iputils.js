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
 * Converts a 32-bit number back to an IPv4 address string.
 * Example: 2130706433 => "127.0.0.1"
 * @param {number} num - 32-bit integer representation of IP.
 * @returns {string} IPv4 address.
 */
export function numberToIp(num) {
	return [
		(num >>> 24) & 0xff,
		(num >>> 16) & 0xff,
		(num >>> 8) & 0xff,
		num & 0xff,
	].join(".");
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

/**
 * Converts an IP range [startIP, endIP] into the minimal list of CIDR blocks covering that range.
 * @param {string} startIP - Starting IPv4 address (e.g. "192.168.0.0").
 * @param {string} endIP - Ending IPv4 address (e.g. "192.168.1.255").
 * @returns {string[]} Array of CIDR blocks covering the range.
 */
export function rangeToCIDRs(startIP, endIP) {
	let start = ipToNumber(startIP);
	let end = ipToNumber(endIP);

	if (start > end) {
		throw new Error("Start IP must be less than or equal to End IP");
	}

	const cidrs = [];

	while (start <= end) {
		let maxSize = 32;

		// Find the largest mask we can apply to the current start address without exceeding the end
		while (maxSize > 0) {
			const mask = ~(2 ** (32 - maxSize) - 1) >>> 0; // subnet mask
			const maskedBase = start & mask;

			if (maskedBase !== start) {
				break;
			}

			const broadcast = start + 2 ** (32 - maxSize) - 1;
			if (broadcast > end) {
				break;
			}

			maxSize--;
		}
		maxSize++;

		cidrs.push(`${numberToIp(start)}/${maxSize}`);

		start += 2 ** (32 - maxSize);
	}

	return cidrs;
}