DROP TABLE IF EXISTS `dnsResponses`;
DROP TABLE IF EXISTS `answers`;
DROP TABLE IF EXISTS `flowlogs`;

CREATE TABLE `answers` (
  `host` varbinary(255) NOT NULL,
  `ip_addresses` varbinary(512) NOT NULL,
  `ttls` varbinary(255) NOT NULL,
  idx bigint UNSIGNED AUTO_INCREMENT,
  UNIQUE KEY (host, ip_addresses, ttls),
  PRIMARY KEY (idx)
) ENGINE=InnoDB;

CREATE TABLE dnsResponses (
  time timestamp NOT NULL,
  src_ip binary(16) NOT NULL,
  dest_ip binary(16) NOT NULL,
  opcode int UNSIGNED NOT NULL,
  resultcode int UNSIGNED NOT NULL,
  answer bigint UNSIGNED NOT NULL,
  FOREIGN KEY (answer) REFERENCES answers(idx)
) ENGINE=InnoDB;

CREATE TABLE `flowlogs` (
  `intervalStart` timestamp NOT NULL,
  `intervalStop` timestamp NOT NULL,
  `addressA` varbinary(16) NOT NULL,
  `addressB` varbinary(16) NOT NULL,
  `transportProtocol` tinyint UNSIGNED NOT NULL,
  `portA` smallint UNSIGNED NOT NULL,
  `portB` smallint UNSIGNED NOT NULL,
  `bytesAtoB` bigint NOT NULL,
  `bytesBtoA` bigint NOT NULL
) ENGINE=InnoDB;
