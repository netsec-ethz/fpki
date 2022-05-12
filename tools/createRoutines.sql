/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Dumping events for database 'fpki'
--

--
-- Dumping routines for database 'fpki'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- -----------------------------------------------------------------------------------------
-- -----------------------------------------------------------------------------------------

-- DELIMITER $$
-- CREATE FUNCTION get_leaf(
-- leafID VARCHAR(33)
-- )
-- RETURNS INT
-- DETERMINISTIC
-- BEGIN
-- 	RETURN 42;
-- END$$
-- DELIMITER ;


-- Recursive Common Table Expression (CTEs):

-- WITH RECURSIVE node_path (idhash,path) AS
-- (
-- 		SELECT idhash,CAST(idhash AS CHAR(5000)) FROM nodes WHERE parentnode IS NULL
--     UNION ALL
-- 		SELECT n.idhash, CONCAT(np.path,HEX(n.idhash))
-- 		FROM node_path AS np JOIN nodes AS n
--         ON np.idhash = n.parentnode
-- )
-- SELECT * FROM node_path WHERE idhash=UNHEX("FF000043A7C4C7520CDDA0A24160987B27D5AED35AA402B34A18D92947B039323F");

-- SELECT HEX(idhash) FROM nodes WHERE idhash = (
-- 	SELECT parentnode FROM nodes WHERE idhash = (
-- 		SELECT UNHEX("FF000043A7C4C7520CDDA0A24160987B27D5AED35AA402B34A18D92947B039323F")
--     )
-- );

-- USE fpki;
-- DROP PROCEDURE IF EXISTS get_leaf;

-- DELIMITER $$
-- CREATE PROCEDURE get_leaf(
-- 	IN leafhash VARCHAR(33)
-- )
-- BEGIN
-- 	SELECT idhash FROM nodes WHERE idhash = leafhash;
-- END$$
-- DELIMITER ;

-- CALL get_leaf(UNHEX(""));

-- ----------------------------------------------------------------------------------------------------

USE fpki;
DROP PROCEDURE IF EXISTS get_leaf;

DELIMITER $$
CREATE PROCEDURE get_leaf(
	IN nodehash VARBINARY(33)
)
BEGIN
		DECLARE hashes BLOB DEFAULT '';
        DECLARE temp VARBINARY(33);
        DECLARE parent VARBINARY(33);

mainloop: LOOP
	IF nodehash IS NULL THEN
		LEAVE mainloop;
	END IF;

	SELECT idhash,parentnode INTO nodehash,parent FROM nodes WHERE idhash = nodehash;

    SET hashes = CONCAT(hashes,nodehash);
    SET nodehash = parent;
END LOOP;
	-- SELECT HEX(hashes);
    SELECT hashes;

END$$
DELIMITER ;

CALL get_leaf(UNHEX("FF000043A7C4C7520CDDA0A24160987B27D5AED35AA402B34A18D92947B039323F"));
