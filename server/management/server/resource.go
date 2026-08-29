package server

type ResourceType string

func (p ResourceType) String() string {
	return string(p)
}

type Resource struct {
	Type ResourceType
	ID   string
}
