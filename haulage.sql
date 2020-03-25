DROP TABLE IF EXISTS `customers`;
DROP TABLE IF EXISTS `static_ips`;
DROP TABLE IF EXISTS `dnsResponses`;
DROP TABLE IF EXISTS `answers`;
DROP TABLE IF EXISTS `flowlogs`;

CREATE TABLE `customers` (
  `imsi` varchar(16) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `raw_down` bigint(15) unsigned DEFAULT '0',
  `raw_up` bigint(15) unsigned DEFAULT '0',
  `data_balance` bigint(15) DEFAULT '10000000',
  `balance` decimal(13,4) DEFAULT '0' COMMENT 'this value is currency-less',
  `bridged` tinyint(1) DEFAULT '1',
  `enabled` tinyint(1) DEFAULT '1',
  `admin` tinyint(1) DEFAULT '0',
  `msisdn` varchar(16) NOT NULL,
  PRIMARY KEY (`imsi`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `static_ips` (
  `imsi` varchar(16) NOT NULL,
  `ip` varchar(16) NOT NULL,
  PRIMARY KEY (`imsi`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `answers` (
  `host` varchar(255) CHARACTER SET ascii NOT NULL,
  `ip_addresses` varchar(416) CHARACTER SET ascii NOT NULL,
  `ttls` varchar(96) CHARACTER SET ascii NOT NULL,
  idx bigint UNSIGNED AUTO_INCREMENT,
  UNIQUE KEY (host, ip_addresses, ttls),
  PRIMARY KEY (idx)
) ENGINE=InnoDB;

CREATE TABLE dnsResponses (
  time DATETIME NOT NULL,
  `srcIp` varbinary(16) NOT NULL,
  `dstIp` varbinary(16) NOT NULL,
  `transportProtocol` tinyint UNSIGNED NOT NULL,
  `srcPort` smallint UNSIGNED NOT NULL,
  `dstPort` smallint UNSIGNED NOT NULL,
  opcode int UNSIGNED NOT NULL,
  resultcode int UNSIGNED NOT NULL,
  answer bigint UNSIGNED NOT NULL,
  FOREIGN KEY (answer) REFERENCES answers(idx)
) ENGINE=InnoDB;

CREATE TABLE `flowlogs` (
  `intervalStart` DATETIME NOT NULL,
  `intervalStop` DATETIME NOT NULL,
  `addressA` varbinary(16) NOT NULL,
  `addressB` varbinary(16) NOT NULL,
  `transportProtocol` tinyint UNSIGNED NOT NULL,
  `portA` smallint UNSIGNED NOT NULL,
  `portB` smallint UNSIGNED NOT NULL,
  `bytesAtoB` bigint NOT NULL,
  `bytesBtoA` bigint NOT NULL
) ENGINE=InnoDB;
