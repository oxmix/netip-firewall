#!/usr/bin/env php
<?php
declare(ticks=1);
pcntl_signal(SIGTERM, function () {
	exit(0);
});

new Tasks;

class Tasks {
	const EACH_ITER = 8;
	public int $iteration = 0;
	public array $info = [
		'host'     => '',
		'cores'    => 0,
		'arch'     => '',
		'cpuModel' => '',
		'osKernel' => ''
	];
	public int $firewallVersion = 0;
	public bool $blackHole = false;
	public int $blackHoleQuantity = 0;
	public array $blackHoleCounter = [];
	public array $blackHoleExists = [];

	public function __construct() {
		cli_set_process_title('netip-firewall');

		if ($this->iteration === 0) {
			$this->info = [
				'host'     => gethostname(),
				'cores'    => (int)shell_exec('nproc'),
				'arch'     => php_uname('m'),
				'cpuModel' => trim(shell_exec(
					"grep -m 1 'model name' /proc/cpuinfo | awk -F':' '{print $2}'")),
				'osKernel' => php_uname('s').' '.php_uname('r')
			];
		}

		while (true) {
			$result = self::request('/firewall/tasks', [
				'iteration' => ++$this->iteration,
				'key'       => getenv('HANDSHAKE_KEY'),

				'uptime'      => floatval(file_get_contents('/proc/uptime')),
				'loadAverage' => implode(', ',
					array_map(function ($n) {
						return round($n, 2);
					}, sys_getloadavg())),
				'host'        => $this->info['host'],
				'cores'       => $this->info['cores'],
				'arch'        => $this->info['arch'],
				'cpuModel'    => $this->info['cpuModel'],
				'osKernel'    => $this->info['osKernel'],

				'firewallVersion'   => $this->firewallVersion,
				'blackHoleQuantity' => $this->blackHoleQuantity,
				'blackHoleCounter'  => $this->blackHoleCounter,
			]);

			if (($result['ok'] ?? false) === true) {

				if (($result['remove'] ?? false) === true) {
					$this->firewall(false, []);
					$this->blackHole(false, []);

					echo 'Do kill this container, sleep 3600 sec...'.PHP_EOL;
					sleep(3600);
					continue;
				}
				if (!empty($result['firewall'])) {
					$firewall = $result['firewall'];

					if ($firewall['version'] !== $this->firewallVersion) {
						$this->firewallVersion = $firewall['version'];
						echo '- exec firewall rules'.PHP_EOL;
						$this->firewall($firewall['enable'], $firewall['rules']);
					}

					$this->blackHole(
						$firewall['blackHole'] && $firewall['enable'],
						$firewall['blackHoleCommands'] ?? []);
				}

			} else {
				echo '- bad request'.PHP_EOL;
				var_dump($result);
				echo '---'.PHP_EOL;

				if (($result['httpCode'] ?? 0) >= 500 && $this->iteration === 1) {
					exit('- iteration: 1 and response code: '.$result['httpCode'].' -> now restart'.PHP_EOL);
				}
			}

			sleep(self::EACH_ITER);;
		}

	}

	public function apiEndpoint(): string {
		return getenv('ENDPOINT') ?: 'https://oxmix.net/api';
	}

	public function request($url, $params = []) {
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, self::apiEndpoint().$url);
		curl_setopt($curl, CURLOPT_HTTPHEADER, [
			'Content-Type: application/json'
		]);
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($params,
			JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		if (self::apiEndpoint() === 'https://localhost/api') {
			curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
		}
		$json = curl_exec($curl);
		$httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$curlErr = curl_error($curl);
		curl_close($curl);

		if ($httpCode != 200) {
			return [
				'ok'         => false,
				'httpCode'   => $httpCode,
				'curlError'  => $curlErr,
				'resultJson' => $json
			];
		}

		if (empty($json)) {
			return [
				'ok'         => false,
				'httpCode'   => $httpCode,
				'curlError'  => $curlErr,
				'resultJson' => $json
			];
		}

		return json_decode($json, true);
	}


	public function firewall(bool $enable, array $rules): void {
		$table = 'netip';

		if (!$enable) {
			echo '- disabling firewall '.PHP_EOL;
			shell_exec("nft add table inet $table");
			shell_exec("nft delete table inet $table");
			shell_exec("nft flush chain ip nat $table");

			return;
		}

		shell_exec("nft add table inet $table");
		shell_exec("nft add chain inet $table input '{ type filter hook input priority 0; policy drop ; }'");
		shell_exec("nft flush chain inet $table input");
		shell_exec("nft add rule inet $table input iif lo accept");
		shell_exec("nft add rule inet $table input ct state related,established accept");
		shell_exec("nft add rule inet $table input ct state invalid drop");

		// containers prerouting control ports
		shell_exec("nft add chain ip nat $table");
		shell_exec("nft flush chain ip nat $table");

		$exists = trim(shell_exec("nft list chain ip nat PREROUTING 2> - "
			."| grep -i 'jump $table' >/dev/null 2>&1 && echo yes"));
		if ($exists !== 'yes') {
			shell_exec("nft insert rule ip nat PREROUTING fib daddr type local counter jump $table");
		}
		// allow traffic from container to host
		shell_exec("nft add rule inet $table input ip saddr "
			."'{ 172.16.0.0/12, 10.0.0.0/8, 100.64.0.0/10, 192.168.0.0/16 }' counter accept");
		shell_exec("nft add rule ip nat $table ip saddr "
			."'{ 172.16.0.0/12, 10.0.0.0/8, 100.64.0.0/10, 192.168.0.0/16 }' counter return");
		shell_exec("nft add rule ip nat $table counter drop");

		foreach ($rules as $e) {
			$protocol = strtolower($e['protocol'] ?? 'tcp');
			$target = strtolower($e['target'] ?? 'drop');

			if ($protocol === 'icmp') {
				shell_exec("nft add rule inet $table input meta l4proto icmp accept");
				shell_exec("nft insert rule ip nat $table meta l4proto icmp return");
				continue;
			}

			$proto = $source = $ports = '';
			if (!empty($protocol)) {
				$proto = 'l4proto '.$protocol;
			}
			if (!empty($e['source'])) {
				$source = ($this->isIPv6($e['source']) ? 'ip6' : 'ip')
					.' saddr '.$e['source'];
			}
			if (!empty($e['ports']) && !empty($protocol)) {
				$ports = $protocol.' dport { '.$e['ports'].' }';
			}

			shell_exec("nft add rule inet $table input meta $proto $source $ports counter ".$target);

			// containers prerouting control ports
			if ($target === 'accept') {
				shell_exec("nft insert rule ip nat $table meta $proto $source $ports counter return");
			}
		}
		shell_exec("nft add rule inet $table input counter drop");
	}

	public function blackHole(bool $enable, $commands = []): void {
		$table = 'netip-blackhole';

		if (!$enable) {
			if (!$this->blackHole) {
				return;
			}
			$this->blackHole = false;

			echo '- blackhole destroying'.PHP_EOL;

			$this->blackHoleQuantity = 0;
			shell_exec("nft delete table inet $table");

			return;
		}

		if (!$this->blackHole) {
			$this->blackHole = true;

			$exists = trim(shell_exec("nft list table inet $table >/dev/null 2>&1 && echo yes"));

			if ($exists !== 'yes') {
				echo '- blackhole initialing'.PHP_EOL;
				$init = [
					"nft add table inet $table",
					"nft add chain inet $table input '{ type filter hook input priority -1; policy accept ; }'",
					"nft add chain inet $table forward '{ type filter hook input priority -1; policy accept ; }'",
					"nft add set inet $table IPv4 '{ type ipv4_addr; flags interval; }'",
					"nft add set inet $table IPv6 '{ type ipv6_addr; flags interval; }'",
					"nft add rule inet $table input ip saddr @IPv4 counter drop",
					"nft add rule inet $table input ip6 saddr @IPv6 counter drop",
					"nft add rule inet $table forward ip saddr @IPv4 counter drop",
					"nft add rule inet $table forward ip6 saddr @IPv6 counter drop"
				];
				foreach ($init as $e) {
					echo shell_exec($e);
				}
			}
		}

		if ($this->iteration === 1) {
			foreach ([4, 6] as $v) {
				@[$_, $i] = explode('elements = {',
					shell_exec("nft list set inet $table IPv$v"), 2);
				if (empty($i)) {
					continue;
				}
				[$ips] = explode('}', $i, 2);
				if (empty($ips)) {
					continue;
				}
				foreach (explode(',', $ips) as $ip) {
					$this->blackHoleQuantity++;
					$this->blackHoleExists[trim($ip)] = 1;
				}
			}
		}

		foreach ($commands as $e) {
			$set = $this->isIPv6($e['ip']) ? 'IPv6' : 'IPv4';
			$act = $e['act'] === 'add' ? 'add' : 'delete';

			$success = trim(shell_exec("nft $act element inet $table $set '{ $e[ip] }'"
				." >/dev/null 2>&1 && echo yes"));

			if ($success !== 'yes')
				continue;

			if ($e['act'] === 'add') {
				if (!isset($this->blackHoleExists[$e['ip']])) {
					$this->blackHoleExists[$e['ip']] = 1;
					$this->blackHoleQuantity++;
				}
			}

			if ($e['act'] === 'del') {
				$this->blackHoleQuantity--;
				unset($this->blackHoleExists[$e['ip']]);
			}
		}

		$if = shell_exec("nft list chain inet $table input")
			.shell_exec("nft list chain inet $table forward");
		preg_match_all('#@(.+?) counter packets ([\d]+) bytes ([\d]+) drop#',
			$if, $stats, PREG_SET_ORDER);
		$this->blackHoleCounter = [
			'IPv4' => ['packets' => 0, 'bytes' => 0],
			'IPv6' => ['packets' => 0, 'bytes' => 0]
		];
		foreach ($stats as $s) {
			$this->blackHoleCounter[$s[1]]['packets'] += $s[2];
			$this->blackHoleCounter[$s[1]]['bytes'] += $s[3];
		}
	}

	public function isIPv6(string $ip): bool {
		[$ip] = explode('/', $ip, 2);

		return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
	}
}
