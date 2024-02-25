package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type User struct {
	ID       int
	Name     string
	Email    string
	Password string
}

type Task struct {
	ID         int
	Title      string
	DueDate    string
	CategoryID int
	IsDone     bool
	UserID     int
}
type Category struct {
	ID     int
	Title  string
	Color  string
	UserID int
}

const ManDarAvardiSerializationMode = "mandaravardi"
const userStoragePath = "user.txt"
const JsonSerialzationMode = "json"

var userStorage []User
var authenticatedUSer *User
var taskStorage []Task
var categoryStorage []Category

var serializationMode string

func main() {

	serializeMode := flag.String("serialize-mode", ManDarAvardiSerializationMode, "serialization mode")
	command := flag.String("command", "no command", "command to run")
	flag.Parse()

	loadUserStorageFromFile(*serializeMode)

	fmt.Println("Hello to TODO app")

	switch *serializeMode {
	case ManDarAvardiSerializationMode:
		serializationMode = ManDarAvardiSerializationMode
	default:
		serializationMode = JsonSerialzationMode

	}

	for {
		runCommand(*command)

		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("please enter another command")
		scanner.Scan()
		*command = scanner.Text()
	}

}

func runCommand(command string) {
	if command != "register-user" && command != "exit" && authenticatedUSer == nil {
		login()
		if authenticatedUSer == nil {
			return
		}
	}
	switch command {
	case "create-task":
		createTask()
	case "create-category":
		createCategory()
	case "register-user":
		registerUser()
	case "login":
		login()
	case "list-task":
		listTask()
	case "exit":
		os.Exit(0)
	default:
		fmt.Println("command is not valid")
	}
}

func createTask() {

	scanner := bufio.NewScanner(os.Stdin)
	var title, duedate, category string
	scanner.Scan()
	fmt.Println("please enter your task name")
	scanner.Scan()
	title = scanner.Text()
	fmt.Println("please enter your task category id")
	scanner.Scan()
	category = scanner.Text()

	categoryID, err := strconv.Atoi(category)
	if err != nil {
		fmt.Printf("category-id is not valid for integer, %v\n", err)

		return
	}

	isFound := false
	for _, c := range categoryStorage {
		if c.ID == categoryID && c.UserID == authenticatedUSer.ID {
			isFound = true

			break
		}
	}
	if !isFound {
		fmt.Println("category is not valid")

		return
	}

	fmt.Println("please enter your task duedate")
	scanner.Scan()
	duedate = scanner.Text()

	task := Task{
		ID:         len(taskStorage) + 1,
		Title:      title,
		DueDate:    duedate,
		CategoryID: categoryID,
		IsDone:     false,
		UserID:     authenticatedUSer.ID,
	}
	taskStorage = append(taskStorage, task)

	fmt.Println("task", title, category, duedate)
}
func createCategory() {
	scanner := bufio.NewScanner(os.Stdin)
	var title, color string
	fmt.Println("please enter your category title ")
	scanner.Scan()
	title = scanner.Text()
	fmt.Println("please enter your category color ")
	scanner.Scan()
	color = scanner.Text()

	category := Category{
		ID:     len(categoryStorage) + 1,
		Title:  title,
		Color:  color,
		UserID: authenticatedUSer.ID,
	}
	categoryStorage = append(categoryStorage, category)

	fmt.Println("category", title, color)
}
func registerUser() {
	scanner := bufio.NewScanner(os.Stdin)
	var id, name, email, password string

	fmt.Println("please enter the name")
	scanner.Scan()
	name = scanner.Text()

	fmt.Println("please enter the email")
	scanner.Scan()
	email = scanner.Text()

	fmt.Println("please enter the password")
	scanner.Scan()
	password = scanner.Text()
	id = email
	fmt.Println("user:", id, email, password)

	user := User{
		ID:       len(userStorage) + 1,
		Name:     name,
		Email:    email,
		Password: hashThePassword(password),
	}

	userStorage = append(userStorage, user)

	writeUserToFile(user)
}

func login() {
	fmt.Println("login process")
	scanner := bufio.NewScanner(os.Stdin)
	var email, password string
	fmt.Println("please enter the email")
	scanner.Scan()
	email = scanner.Text()

	fmt.Println("please enter the password")
	scanner.Scan()
	password = scanner.Text()

	for _, user := range userStorage {
		if user.Email == email && user.Password == password {
			authenticatedUSer = &user

			break
		}
	}
	if authenticatedUSer == nil {
		fmt.Println("The email or password is not correct")

	}

}

func listTask() {
	for _, task := range taskStorage {
		if task.UserID == authenticatedUSer.ID {
			fmt.Println(task)
		}
	}
}

func loadUserStorageFromFile(serializationMode string) {

	//solution one
	//file, err := os.Open(userStoragePath)
	//if err != nil {
	//	fmt.Println("can't open the file", err)
	//}
	//
	//var finalData []byte
	//for {
	//	var data = make([]byte, 1024)
	//	numberOfReadData, oErr := file.Read(data)
	//	if oErr != nil {
	//		fmt.Println("can't read file", oErr)
	//		return
	//	}
	//
	//	finalData = append(finalData, data[:numberOfReadData]...)
	//
	//	if oErr == io.EOF {
	//		fmt.Println("the file is completely read", oErr)
	//		break
	//	}
	//}

	// solution two

	finalData, err := os.ReadFile(userStoragePath)
	if err != nil {
		fmt.Println("can't read the file", err)
	}

	var dataStr = string(finalData)

	userSlice := strings.Split(dataStr, "\n")

	for _, u := range userSlice {
		var userStruct = User{}
		switch serializationMode {
		case ManDarAvardiSerializationMode:

			var dErr error
			userStruct, dErr = deserilizeFromManDaravardi(u)
			if dErr != nil {
				fmt.Println("can't deserialize user record to user struct", dErr)

				return
			}
		case JsonSerialzationMode:
			if u[0] != '{' && u[len(u)-1] != '}' {

				continue
			}

			uErr := json.Unmarshal([]byte(u), &userStruct)
			if uErr != nil {
				fmt.Println("can't deserialize user record to user struct with json mode", uErr)

				return
			}

		}

		userStorage = append(userStorage, userStruct)
	}
}

func writeUserToFile(user User) {

	var file *os.File

	file, err := os.OpenFile(userStoragePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("can't create or open file", err)

		return
	}

	defer func() {
		cErr := file.Close()
		if cErr != nil {
			fmt.Println("can't close the file", cErr)
		}
	}()

	var data []byte

	if serializationMode == ManDarAvardiSerializationMode {
		data = []byte(fmt.Sprintf("id: %d, name: %s, email: %s, password:%s ",
			user.ID, user.Name, user.Email, user.Password))
	} else if serializationMode == JsonSerialzationMode {
		//json

		var jErr error
		data, jErr = json.Marshal(user)
		if jErr != nil {
			fmt.Println("can't marshal user struct to json", err)

			return
		}
	} else {
		fmt.Println("invalid serialization mode")

		return
	}

	numberOfWrittenBytes, wErr := file.Write(data)
	if wErr != nil {
		fmt.Printf("can't write to the file %v\n", wErr)

		return
	}

	fmt.Println("numberOfWrittenBytes", numberOfWrittenBytes)

}

func deserilizeFromManDaravardi(userStr string) (User, error) {

	if userStr == "" {

		return User{}, errors.New("user string is empty")
	}

	var user = User{}

	userFields := strings.Split(userStr, ",")
	for _, field := range userFields {
		fmt.Println(field)
		values := strings.Split(field, ": ")
		if len(values) != 2 {
			fmt.Println("field is not valid is skipping ... ", len(values))

			continue
		}
		fieldName := strings.ReplaceAll(values[0], " ", "")
		fieldValue := values[1]

		switch fieldName {
		case "id":
			id, err := strconv.Atoi(fieldValue)
			if err != nil {
				fmt.Println("strconv err", err)

				return User{}, errors.New("strconv error")
			}
			user.ID = id
		case "name":
			user.Name = fieldValue
		case "email":
			user.Email = fieldValue
		case "password":
			user.Password = fieldValue
		}

	}
	return user, nil

}

func hashThePassword(password string) string {
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}
