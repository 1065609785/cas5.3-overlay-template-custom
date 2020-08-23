DROP TABLE IF EXISTS `cas`;
CREATE TABLE `cas` (
  `username` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `phone` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `age` int(11) DEFAULT NULL,
  `sex` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `mail` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


INSERT INTO `cas` VALUES ('zsy', '202cb962ac59075b964b07152d234b70', 'admin', '15755365206', 20, '男', '1@qq.com');
INSERT INTO `cas` VALUES ('lishi', '$2a$10$1eDsuyXXN4q0Zhs7Gt19l.yyAORFAFINDGOyE61oPBnSzG6bw8bo6', 'admin', '15755365206', 22, '男', '2@qq.com');
