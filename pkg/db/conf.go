package db

const KeyDBName = "DBNAME"

// Configuration for the db connection
type Configuration struct {
	Dsn         string
	Values      map[string]string
	CheckSchema bool // indicates if opening the connection checks the health of the schema
}

type ConfigurationModFunction func(*Configuration) *Configuration

func NewConfig(modifiers ...ConfigurationModFunction) *Configuration {
	c := &Configuration{
		Values: map[string]string{
			KeyDBName: "fpki",
		},
	}
	for _, fcn := range modifiers {
		c = fcn(c)
	}
	return c
}

func WithDB(dbName string) ConfigurationModFunction {
	return func(c *Configuration) *Configuration {
		c.Values[KeyDBName] = dbName
		return c
	}
}
