package types

type User struct {
	Email               string `json:"email"`
	User_id             string `json:"user_id"`
	Name                string `json:"name"`
	Attack_defense_role string `json:"attack_defense_role"`
}

type Feedback struct {
	Name       string `json:"name"`
	Feedback   string `json:"feedback"`
	Created_at string `json:"created_at"`
	ID         int    `json:"id"`
	Type       string `json:"type"`
}

type Challenge struct {
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	ContainerNames []string `json:"container_names"`
	Points         int      `json:"points"`
	Category       string   `json:"category"`
	Difficulty     string   `json:"difficulty"`
	Hint           string   `json:"hint"`
	Attachments    string   `json:"attachments"`
	IsSolved       bool     `json:"issolved"`
	Solves         int      `json:"solves"`
}

type Lab struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	DockerFile     string   `json:"dockerfile"`
	Category       string   `json:"category"`
	ContainerNames []string `json:"container_names"`
	IsSolved       bool     `json:"issolved"`
	IsCTF          string   `json:"isctf"`
	Shown          string   `json:"shown_string"`
	ShownBoolean   bool     `json:"shown"`
}

type Category struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	NumberOfLabs int64  `json:"number_of_labs"`
}

type UserLogin struct {
	EmailOrID string `json:"email_or_id"`
	Role      string `json:"role"`
	Password  string `json:"password"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type UserRegister struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type Message struct {
	Sender  string `json:"sender"`
	Message string `json:"message"`
	Time    string `json:"time"`
	Role    string `json:"role"`
}

type RequestUpdateAccount struct {
	Name        string `json:"name"`
	OldPassword string `json:"password_current"`
	NewPassword string `json:"password_new"`
}
