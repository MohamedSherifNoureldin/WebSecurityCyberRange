package db

import (
	"fmt"

	"github.com/lib/pq"
)

func AddLab(name, description, fileBytes string, services []string, category, isctf string) error {
	_, err := DB.Exec("INSERT INTO labs (name, description, composefile, container_names,category,isctf) VALUES ($1, $2, $3, $4, $5, $6)", name, description, fileBytes, pq.Array(services), category, isctf)
	if err != nil {

		return err
	}

	return nil

}

func DeleteLab(name string) error {
	_, err := DB.Exec("DELETE FROM labs WHERE name = $1", name)
	if err != nil {
		return err
	}

	return nil
}

func AddCategory(name string) error {
	_, err := DB.Exec("INSERT INTO lab_categories (name) VALUES ($1)", name)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func DeleteCategory(name string) error {
	_, err := DB.Exec("DELETE FROM lab_categories WHERE name = $1", name)
	if err != nil {
		return err
	}

	_, err = DB.Exec("DELETE FROM labs WHERE category = $1", name)
	if err != nil {
		return err
	}

	return nil
}

func UpdateLabStatus(name, hidden string) error {
	_, err := DB.Exec("UPDATE labs SET shown = $1 WHERE name = $2", hidden, name)
	if err != nil {
		return err
	}

	return nil
}
