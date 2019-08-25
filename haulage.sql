DROP TABLE IF EXISTS `dnsResponses`;
DROP TABLE IF EXISTS `answers`;
DROP TABLE IF EXISTS `flowlogs`;
DROP TABLE IF EXISTS `servicelogs`;

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

CREATE TABLE `servicelogs` (
  `service` varchar(255) CHARACTER SET ascii NOT NULL,
  `aliases` varchar(255) CHARACTER SET ascii NOT NULL,
  `totalbytes` bigint NOT NULL,
  `numusers` smallint UNSIGNED NOT NULL,
  idx bigint UNSIGNED AUTO_INCREMENT,
  UNIQUE KEY (service),
  PRIMARY KEY (idx)
) ENGINE=InnoDB;

INSERT INTO `servicelogs`(`service`, `aliases`, `totalbytes`, `numusers`) VALUES 
('total', '', 0, 0),
('whatsapp', 'whatsapp', 0, 0),
('google', 'google, gmail', 0, 0),
('facebook', 'facebook, fbcdn, fbsbx', 0, 0),
('twitter', 'twitter, twimg', 0, 0),
('youtube', 'youtube, ytimg', 0, 0),
('instagram', 'instagram', 0, 0),
('wikipedia', 'wikipedia', 0, 0),
('akamai', 'akamai', 0, 0),
('amazonaws', 'amazonaws', 0, 0),
('cloudfront', 'cloudfront', 0, 0),
('cloudflare', 'cloudflare', 0, 0);
