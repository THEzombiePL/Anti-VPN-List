import fs from "node:fs/promises";
import { ipToNumber, cidrToRange } from "../utils/iputils.js";

const ipList = [
	"1.1.1.1",
	"8.8.8.8",
	"192.168.1.1",
	"203.0.113.50",
	"16.88.0.0",
	"175.201.245.187",
	"223.255.199.161",
	"193.42.98.74",
];

/**
 * Checks if an IP (as number) is blocked by any of the given ranges using binary search.
 * @param {number} ipNum - IP address as a number.
 * @param {Array<[number, number]>} ranges - Array of [start, end] IP ranges (sorted by start).
 * @returns {boolean} True if blocked, false otherwise.
 */
function isBlocked(ipNum, ranges) {
	let left = 0;
	let right = ranges.length - 1;

	while (left <= right) {
		const mid = Math.floor((left + right) / 2);
		const [start, end] = ranges[mid];

		if (ipNum < start) {
			right = mid - 1;
		} else if (ipNum > end) {
			left = mid + 1;
		} else {
			return true;
		}
	}

	return false;
}

/**
 * Loads the blocked IP list, parses CIDRs, and checks the test IPs.
 */
async function checkIPs() {
	try {
		console.log("Loading blocked IP list...");
		const startTime = Date.now();

		const data = await fs.readFile("malicious-ips.txt", "utf-8");
		const cidrs = data
			.split("\n")
			.map((line) => line.trim())
			.filter(Boolean)
			.map((line) => (line.includes("/") ? line : `${line}/32`));

		const ranges = cidrs.map(cidrToRange);
		const totalIPs = ranges.reduce(
			(acc, [start, end]) => acc + (end - start + 1),
			0
		);
		console.log(
			`Total number of IP addresses covered by CIDRs: ${totalIPs.toLocaleString()}`
		);
		// Sort ranges by start
		ranges.sort((a, b) => a[0] - b[0]);
		const elapsed = (Date.now() - startTime) / 1000;
		console.log(
			`Loaded ${ranges.length} CIDR ranges in ${elapsed.toFixed(2)}s`
		);
		console.log(
			`Memory usage: ${(
				process.memoryUsage().heapUsed /
				1024 /
				1024
			).toFixed(2)} MB`
		);

		const checkStart = Date.now();
		for (const ip of ipList) {
			const ipNum = ipToNumber(ip);
			const blocked = isBlocked(ipNum, ranges);
			const duration = Date.now() - checkStart;

			console.log(
				`IP ${ip} is ${
					blocked ? "blocked ❌" : "allowed ✅"
				} (${duration}ms)`
			);
		}
	} catch (err) {
		if (err.code === "ENOENT") {
			console.error(
				"File malicious-ips.txt does not exist! Run download.js first to generate it."
			);
		} else {
			console.error("File read error:", err);
		}
	}
}

checkIPs();
