import { Readable } from "node:stream";
import zlib from "node:zlib";
import readline from "node:readline";
import { writeFile } from "node:fs/promises";
import IPCIDR from "ip-cidr";
import { RadixTree } from "../utils/RadixTree.js";
import {
	ipToBinary,
	cidrToBinaryPrefix,
	rangeToCIDRs,
} from "../utils/iputils.js";

const urls = [
	"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
	"https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/all.txt",
	"https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz",
	"https://github.com/firehol/blocklist-ipsets/raw/master/firehol_anonymous.netset",
];

const FILE_NAME = "malicious-ips.txt"; // Output file name
const RETRY_ATTEMPTS = 3;
const RETRY_DELAY = 2000;

/**
 * Checks if we're in a TTY environment (terminal with cursor support)
 * @returns {boolean} True if TTY is available
 */
const isTTY = () => {
	return (
		process.stdout.isTTY &&
		typeof process.stdout.clearLine === "function" &&
		typeof process.stdout.cursorTo === "function"
	);
};

/**
 * Displays progress in the terminal (overwrites the current line if TTY available).
 * @param {string} message - Message to display.
 */
const logProgress = (message) => {
	if (isTTY()) {
		process.stdout.clearLine(0);
		process.stdout.cursorTo(0);
		process.stdout.write(message);
	} else {
		// In non-TTY environment, just log normally
		console.log(message);
	}
};

/**
 * Clears the current line and moves cursor to start (TTY only)
 */
const clearLine = () => {
	if (isTTY()) {
		process.stdout.clearLine(0);
		process.stdout.cursorTo(0);
	}
};

/**
 * Class responsible for downloading, processing, and filtering CIDR/IP lists.
 */
class CIDRProcessor {
	constructor() {
		this.asnSet = new Set();
		this.asnameSet = new Set();
		this.cidrMap = new Map();
	}
	/**
	 * Normalizes the ASName to a simplified format (uppercase, no special characters, no suffixes like LLC, GmbH, Inc, Ltd, S.A., etc.)
	 * @param {string} name
	 * @returns {string}
	 */
	normalizeASName(name) {
		if (!name) return "";
		if (name.includes("PACKETHUB")) return "PACKETHUB";
		if (name.includes("VULTR")) return "VULTR";
		// Removes special characters, converts to uppercase, removes suffixes
		return name
			.replace(/[,\-]/g, " ")
			.replace(
				/(\,\s*|\s+)?(LLC|GMBH|INC|LTD|S\.A\.|S\.A|SP\.?\s*Z\s*O\.?\s*O\.?|SPOLKA|SPÓŁKA|CORP|COMPANY|LIMITED|PLC|AG|BV|SRL|SAS|SA|AB|AS|NV|OY|KG|KFT|OOO|Z\s*O\s*O|CO|ONLINE)\b/gi,
				""
			)
			.replace(/\s+/g, " ")
			.trim()
			.toUpperCase();
	}

	/**
	 * Converts a 32-bit unsigned integer to an IPv4 address string.
	 * @param {number} n - 32-bit unsigned integer.
	 * @returns {string} IPv4 address.
	 */
	u32ToIP(n) {
		return `${n >>> 24}.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`;
	}

	/**
	 * Converts an IP range to an array of CIDRs.
	 * @param {string} startIP - Start IP address.
	 * @param {string} endIP - End IP address.
	 * @returns {string[]} Array of CIDR strings.
	 */
	rangeToCIDRs(startIP, endIP) {
		try {
			const cidr = new IPCIDR(`${startIP}-${endIP}`);
			return cidr.toArray({ type: "cidr" }) || [];
		} catch (error) {
			console.error(`[ERROR] Invalid IP range: ${startIP}-${endIP}`);
			return [];
		}
	}

	/**
	 * Fetches a URL with retry logic.
	 * @param {string} url - URL to fetch.
	 * @param {number} [attempt=1] - Current attempt number.
	 * @returns {Promise<Response>} Fetch response.
	 */
	async fetchWithRetry(url, attempt = 1) {
		try {
			const response = await fetch(url);
			if (!response.ok)
				throw new Error(`HTTP error! status: ${response.status}`);
			return response;
		} catch (error) {
			if (attempt >= RETRY_ATTEMPTS) throw error;
			console.log(`🔄 [INFO] Retry attempt ${attempt} for ${url}`);
			await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY));
			return this.fetchWithRetry(url, attempt + 1);
		}
	}

	/**
	 * Processes a single URL, parsing and storing CIDRs/IPs.
	 * @param {string} url - URL to process.
	 */
	async processUrl(url) {
		logProgress(`[INFO] 🌐 Fetching ${url}...`);
		const startTime = Date.now();
		try {
			const response = await this.fetchWithRetry(url);
			let stream = Readable.fromWeb(response.body);
			if (url.endsWith(".gz")) {
				stream = stream.pipe(zlib.createGunzip());
			}

			const rl = readline.createInterface({
				input: stream,
				crlfDelay: Infinity,
			});

			let entries = 0;
			for await (const line of rl) {
				const trimmedLine = line.trim();
				if (!trimmedLine || trimmedLine.startsWith("#")) continue;
				entries++;

				if (url.includes("iptoasn.com")) {
					const [startIpU32, endIpU32, asn, country, asname] =
						trimmedLine.split("\t");
					const normAsname = this.normalizeASName(asname);
					// Check by ASN or by normalized ASName (contains, ignoreCase)
					let asnameMatch = false;
					if (normAsname && this.asnameSet.size > 0) {
						for (const ref of this.asnameSet) {
							// console.log({normAsname, ref});
							if (
								normAsname.includes(ref) ||
								ref.includes(normAsname)
							) {
								asnameMatch = true;
								break;
							}
						}
					}
					// if (asnameMatch && !this.asnSet.has(asn)) {
					//  console.log(
					//      `[WARN] ASName "${normAsname} ${asname}" matched but ASN "${asn}" not found in ASN set.`
					//  );
					// }
					if (this.asnSet.has(asn) || asnameMatch) {
						const startIP = this.u32ToIP(+startIpU32);
						const endIP = this.u32ToIP(+endIpU32);
						for (const cidr of rangeToCIDRs(startIP, endIP)) {
							this.cidrMap.set(cidr, true);
						}
					}
				} else if (url.includes("NullifiedCode")) {
					if (trimmedLine.startsWith("AS")) {
						const [as, ...asnameParts] = trimmedLine.split(" ");
						this.asnSet.add(as.substring(2));
						// Add normalized ASName to asnameSet
						const asnameRaw = asnameParts.join(" ").trim();
						if (asnameRaw) {
							const norm = this.normalizeASName(asnameRaw);
							// console.log({ norm, asnameRaw });
							if (norm) this.asnameSet.add(norm);
						}
					}
				} else {
					this.cidrMap.set(trimmedLine, true);
				}
			}

			const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
			clearLine();
			console.log(
				`[INFO] ✅ Finished processing ${url} (${entries} lines, ${elapsed}s)`
			);
		} catch (error) {
			if (isTTY()) {
				process.stdout.write("\n");
			}
			console.error(
				`[ERROR] ❌ An error occurred while processing ${url}:`,
				error
			);
		}
	}

	/**
	 * Filters out CIDRs/IPs that are contained within broader CIDRs using a RadixTree.
	 * @returns {Set<string>} Set of unique, non-overlapping CIDRs/IPs.
	 */
	filterContainedCIDRsRadix() {
		console.log("[INFO] 🔁 Starting CIDR filtering (RadixTree)...");
		const startTime = Date.now();
		const result = [];
		const tree = new RadixTree();
		const cidrs = [...this.cidrMap.keys()].sort((a, b) => {
			const isCidrA = a.includes("/");
			const isCidrB = b.includes("/");
			if (isCidrA && isCidrB) {
				const lenA = parseInt(a.split("/")[1]);
				const lenB = parseInt(b.split("/")[1]);
				return lenA - lenB;
			} else if (isCidrA) {
				return -1;
			} else if (isCidrB) {
				return 1;
			} else {
				return 0;
			}
		});

		const totalCidrs = cidrs.length;
		let lastLogTime = Date.now();

		for (let i = 0; i < totalCidrs; i++) {
			const cidr = cidrs[i];
			const binaryPrefix = cidr.includes("/")
				? cidrToBinaryPrefix(cidr)
				: ipToBinary(cidr);
			if (!tree.search(binaryPrefix)) {
				result.push(cidr);
				tree.insert(binaryPrefix);
			}

			const now = Date.now();
			if (now - lastLogTime > 1000 || i === totalCidrs - 1) {
				const percentage = (((i + 1) / totalCidrs) * 100).toFixed(2);
				const elapsed = ((now - startTime) / 1000).toFixed(1);
				logProgress(
					`[INFO] Filtering: ${percentage}% (${
						i + 1
					}/${totalCidrs}) [${elapsed}s]`
				);
				lastLogTime = now;
			}
		}

		if (isTTY()) {
			process.stdout.write("\n");
		}

		const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
		console.log(
			`[INFO] CIDR filtering (RadixTree) finished (${result.length} CIDRs, ${elapsed}s)`
		);
		return new Set(result);
	}

	/**
	 * Main process: downloads, parses, filters, and saves the CIDR/IP list.
	 */
	async process() {
		console.log("🚀 Starting IP list download and processing...");

		const asnUrl = urls.find((url) => url.includes("NullifiedCode"));
		if (asnUrl) {
			await this.processUrl(asnUrl);
			console.log(
				`[INFO] Collected ${this.asnSet.size} ASNs and ${this.asnameSet.size} ASNames to filter by.`
			);
		}

		const otherUrls = urls.filter((url) => !url.includes("NullifiedCode"));
		await Promise.all(otherUrls.map((url) => this.processUrl(url)));

		const filteredCIDRs = this.filterContainedCIDRsRadix();
		await writeFile(FILE_NAME, [...filteredCIDRs].join("\n"), "utf-8");
		console.log(
			`[INFO] Saved ${filteredCIDRs.size} filtered IPs/CIDRs to ${FILE_NAME}`
		);
	}
}

// Start the process
(async () => {
	try {
		const processor = new CIDRProcessor();
		await processor.process();
	} catch (error) {
		console.error("[ERROR] Fatal error occurred:", error);
		process.exit(1);
	}
})();
