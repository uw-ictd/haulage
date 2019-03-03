DROP TABLE IF EXISTS `dnsResponses`;
DROP TABLE IF EXISTS `answers`;
DROP TABLE IF EXISTS `flowlogs`;

CREATE TABLE `answers` (
  `host` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
  `ip_addresses` varchar(512) CHARACTER SET ascii NOT NULL,
  `ttls` varchar(255) CHARACTER SET ascii NOT NULL,
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
