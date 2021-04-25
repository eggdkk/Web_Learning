const terms = ['security', 'CTF', 'pwn', 'pwnable', 'pwning', 'crypto', 'RSA', 'XSS', 'sqli', 'injection', 'array injection', 'log injection', 'LLL', 'forensics', 'reverse', 'reverse engineering', 'stege', 'misc', 'web', 'back engineering', 'Linux', 'DLL injection', 'ping', 'DNS', 'API', 'DDOS', 'DoS', 'exploit', 'Trivia', 'SSL', 'hooking', 'memory', 'volatility', 'dump', 'tcpdump', 'pcap', 'wireshark', 'port', 'TLS', 'DNSSEC', 'infosec', 'vulnerability', 'risk', 'Advanced persistent threat', 'Backdoors', 'Bootkits', 'Computer crime', 'Viruses', 'Denial of service', 'Eavesdropping', 'Exploits', 'Keyloggers', 'Logic bombs', 'Malware', 'Payloads', 'Phishing', 'Ransomware', 'Rootkits', 'Screen scrapers', 'Spyware', 'Trojans', 'Vulnerabilities', 'Web shells', 'Web application security', 'Worms', 'encryption', 'pentest', 'key', 'cipher', 'Confidentiality', 'Integrity', 'flag', 'policy', 'Defense', 'jail', 'python', 'ruby', 'php', 'bash', 'wargame', 'sniffing', 'programming', 'cryptanalysis', 'DEFCON', 'attack', 'hack', 'hacker', 'recon', 'Diffie–Hellman', 'n-bit', 'public-key ', 'word cloud', 'network security', 'network', 'security', 'cloud', 'connection', 'technology', 'internet', 'business', 'communication', 'social', 'networking', 'weaknesses', 'Cracker', 'web', 'data', 'connect', 'concept', 'wireless', 'algorithm', 'WPA', 'DES', 'finite', 'structure', 'server', 'bubble', 'PPC', 'rot13', 'key exchange', 'Hacktivist', 'jeopardy', 'scanner', 'Spoofing', 'Keystroke', 'firewall', 'AES', 'RE', 'reverse enginnering', 'heap spray', 'buffer overflow', 'dark art', 'cutter', 'radare2', 'IDA Pro', 'integrity', 'MAC', 'key', 'CBC-MAC', 'forensics', 'DEFCONeverse enginn', 'Zero knowledge proof', 'Smart Contract', 'control hijacking', 'PSK', 'pwn', 'writeup', 'kernel vulnerability exploit', 'backdoor', 'ssh', 'daemon', 'bash', 'gdb', 'XSS', 'sqli', 'rop', 'RSA', 'reverse engineering', 'ruby', 'remote', 'root', 'radare2', 'race-condition', 'rce', 'query', 'qrcode', 'web', 'writeup', 'wireshark', 'warm-up', 'windows', 'windbg', 'wireless', 'elf', 'exploit', 'exif', 'ethereum', 'elliptic', 'exploiting', 'env', 'encryption', 'encoding', 'trivia', 'terminal', 'threat', 'tcp', 'url-encode', 'unix', 'use-after-free', 'udp', 'injection', 'ios', 'IDA', 'irc', 'obfuscated', 'overflow', 'pwn', 'php', 'python', 'programming', 'prime', 'penetration', 'ppc', 'pwnable', 'programming', 'authentication', 'AES', 'android', 'apache', 'admin', 'arm64', 'arch', 'arbitrary-code-execution', 'ARP poisoning', 'attack', 'api hooking', 'apk', 'api', 'asm', 'sqli', 'stego', 'script', 'security', 'sql', 'sql injection', 'stegano', 'sandbox', 'des', 'discord', 'database', 'ddos', 'dns', 'diffie-hellman', 'forensics', 'fuzzing', 'filesystem', 'fingerprinting', 'firmware', 'fibonacci', 'gdb', 'gcc', 'go', 'hack', 'heartbleed', 'heap-overflow', 'heap', 'honeypot', 'hash', 'javascript', 'jvm', 'jailbreak', 'jwt', 'jit', 'kali', 'kernel', 'keylogger', 'kubernetes', 'libc', 'linux', 'leak', 'login', 'lattice', 'llvm', 'zpool', 'zfs', 'zip', 'zsh', 'xss', 'x86', 'x64', 'xml', 'xml-injection', 'crypto', 'c++', 'c', 'coding', 'crack', 'code-injection', 'certificate', 'crawler', 'cyber-security', 'CTF', 'curl', 'cipher', 'cookies', 'collision', 'captcha', 'CSRF', 'challenge', 'clang', 'cmd', 'vm', 'virus', 'vim', 'vpn', 'vulnerability', 'base64', 'bruteforce', 'buffer-overflow', 'burpsuite', 'bytecode', 'bug', 'bitcoin', 'binwalk', 'binary', 'bit', 'baby', 'backdoor', 'bsqli', 'blockchain', 'blind sqli', 'nosql', 'nmap', 'network', 'ntp', 'ntfs', 'null', 'null-byte-injection', 'nginx', 'nc', 'misc', 'malware', 'mysql', 'mongodb', 'miscellaneous', 'mitm', 'metasploit', 'memory-leak', 'movfuscated', 'md5', 'sweet32', 'heartbleed', 'meltdown', 'spectre', 'Control-flow integrity', 'Canary', 'Exploit', 'NX', 'ASLR', 'integer overflow', 'heap overflow', 'stack overflow', 'OWASP', 'pentest', 'spoofing', 'ping flood', 'least privilege', 'DAC', 'MAC', 'RBAC', 'setuid', 'privilege separation'];
const list = terms.map(x => [x,Math.floor(Math.random() * (6)) +4]);
var colors = ['#5F72E4','#56E8C8','#ABFF6B','#E8C556','#FF875E'];

WordCloud(document.getElementById('html-canvas'), {
        list,
        weightFactor: function (size) {
            return Math.pow(size, 1.6) * $('#html-canvas').width() / 1024;
        }
        ,
        color: function (word, weight) {
            return colors[Math.floor(Math.random()*colors.length)];
        },
        rotateRatio: 0.5,
        rotationSteps: 2,
        backgroundColor: '#f8f9fe',
        drawOutOfBound: false,
    shape: 'pentagon'
    }

 );

        var clock = $('.clock').FlipClock(
        7700 ,{
    clockFace: 'DailyCounter',
        countdown: true,
        showSeconds: false
        }
    );