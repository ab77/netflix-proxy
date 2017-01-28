BEGIN; 

CREATE TABLE "DDNS"(
	"ID" Integer PRIMARY KEY AUTOINCREMENT,
	"created" DateTime DEFAULT CURRENT_TIMESTAMP,
	"user_id" Integer NOT NULL,
	"last_ipaddr" Text,
	"domain" Text NOT NULL  );

PRAGMA user_version = 1;

END; 
