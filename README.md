# Anti-VPN List Generator

Automatically generates CIDR and IP blocklists containing data centers, VPNs, hosting providers, and malicious IPs. The lists are updated every 4 hours **and daily at 06:00 UTC** via GitHub Actions.

## 🎯 Sources

* **Firehol Anonymous:** List of anonymous IP addresses
* **Nullified ASN:** List of data center and VPN ASNs
* **X4B Datacenter:** List of data center and VPN IP ranges
* **IP2ASN:** IP to ASN mapping

## 📁 File Structure

```
├── .github/workflows/
│   └── generate-list.yml    # GitHub Actions workflow
├── scripts/
│   ├── download.js          # Data fetching script
├── example/
│   ├── index.js             # Example usage
├── malicious-ips.txt        # Generated list of IP addresses and CIDR ranges
└── README.md
```

## ⚙️ How It Works

### Automated Triggers

* **Every 4 hours**
* **Daily at 06:00 UTC**
* **On push** to `scripts/download.js`
* **Manually** via GitHub Actions UI


### Generation Process

1. **Download data** from multiple sources, including:

   * X4BNet datacenter IPs (plain text)
   * NullifiedCode ASN list (plain text)
   * IPtoASN IP ranges (compressed TSV)
   * Firehol anonymous IPs (plain text)

2. **Parse and process data line-by-line:**

   * Skip empty and commented lines.
   * From NullifiedCode ASN list, collect ASNs (numbers) to a set.
   * From IPtoASN data, convert start/end IPs from 32-bit unsigned integers to IPv4 strings, and **only keep IP ranges whose ASN matches the collected ASN set**.
   * For other sources, treat each line as an IP or CIDR and add directly to the collection.

3. **Convert IP ranges to CIDRs** when applicable (especially for IPtoASN ranges).

4. **Filter and deduplicate CIDRs and IPs:**

   * Sort CIDRs by prefix length.
   * Use a Radix Tree to efficiently remove CIDRs that are contained within broader CIDRs.
   * This filtering reduces overlaps and redundant entries, ensuring an optimized list.

5. **Save the resulting filtered list** to a file (e.g., `malicious-ips.txt`).

6. **Log progress and errors** at each step, including retries on fetch failures.

## 📥 Download

### Latest Version

```bash
wget https://raw.githubusercontent.com/THEzombiePL/Anti-VPN-List/main/malicious-ips.txt
```

### From Releases

```bash
wget https://github.com/THEzombiePL/Anti-VPN-List/releases/latest/download/malicious-ips.txt

```

## 🔧 Local Usage

```bash
npm install ip-cidr
npm run start
```

## 📈 Monitoring

The GitHub Actions workflow maintains:

* **malicious-ips.txt** — main IPs and CIDR list
* **Release notes** — metadata for each update

## 📝 License

This project uses data from public repositories and sources, each with its own license:

- **FireHOL blocklists**  
  FireHOL blocklists repo does not have a clear open source license. The lists are collected from many public sources and meant to help improve internet security. Please check each source's license before using, as some lists may have specific restrictions.

- **X4B Network**  
  The [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) repository is licensed under MIT. You can use, modify, and distribute the data freely, including for commercial use, as long as you keep the license and credits.

- **Nullified Code ASN Lists**  
  The [NullifiedCode/ASN-Lists](https://github.com/NullifiedCode/ASN-Lists) repo is under GNU GPL v3.0. You can use and modify it, but derivative works must also be shared under the same GPL license.

- **IPtoASN data**  
  Data from [IPtoASN](https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz) is public domain (PDDL). You can use it without restrictions or attribution.

**Note:** Always verify the original license of each list before use, especially for FireHOL data, since some may have additional restrictions.
