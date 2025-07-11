import { IpChecker } from "../utils/IpChecker.js"; // dostosuj ścieżkę
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

const checker = new IpChecker();

try {
	await checker.load("malicious-ips.txt");

	for (const ip of ipList) {
		const result = checker.isBlocked(ip)
			? "blocked ❌"
			: "allowed ✅";
		console.log(`IP ${ip} is ${result}`);
	}
} catch (err) {
	console.error("Failed to load CIDRs or check IPs:", err.message);
}