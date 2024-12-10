package admin

import (
	"cyberrange/utils"
	"math/rand"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type Usage struct {
	Memory map[string]string `json:"memory"`
	CPU    []CPUUsage        `json:"cpu"`
	Disk   map[string]string `json:"disk"`
}

type CPUUsage struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Color string `json:"color"`
}

var colors = []string{
	"red", "orange", "green", "sky", "blue", "indigo", "purple", "pink",
	"lime", "fuchsia", "yellow", "cyan", "teal", "emerald", "rose", "amber", "violet",
}

func getMemoryUsage() (map[string]string, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"total":       strconv.FormatUint(v.Total, 10),
		"available":   strconv.FormatUint(v.Available, 10),
		"used":        strconv.FormatUint(v.Used, 10),
		"usedPercent": strconv.FormatFloat(v.UsedPercent, 'f', 2, 64),
	}, nil
}

func getCPUUsage() ([]CPUUsage, error) {
	cpus, err := cpu.Percent(0, true)
	if err != nil {
		return nil, err
	}

	randGenerator := rand.New(rand.NewSource(time.Now().UnixNano()))
	randGenerator.Shuffle(len(colors), func(i, j int) { colors[i], colors[j] = colors[j], colors[i] })

	cpuUsages := make([]CPUUsage, len(cpus))
	for i, val := range cpus {
		cpuUsages[i] = CPUUsage{
			Label: "core" + strconv.Itoa(i),
			Value: strconv.FormatFloat(val, 'f', 2, 64),
			Color: colors[i%len(colors)],
		}
	}
	return cpuUsages, nil
}

func getDiskUsage() (map[string]string, error) {
	d, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"total": strconv.FormatUint(d.Total, 10),
		"free":  strconv.FormatUint(d.Free, 10),
		"used":  strconv.FormatUint(d.Used, 10),
	}, nil
}

func GetUsage(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")
	role := utils.GetRole(token)
	if role != "admin" {
		return c.JSON(403, map[string]string{"error": "Unauthorized"})
	}

	ram, err := getMemoryUsage()
	if err != nil {
		return err
	}

	cpu, err := getCPUUsage()
	if err != nil {
		return err
	}

	disk, err := getDiskUsage()
	if err != nil {
		return err
	}

	usage := &Usage{
		Memory: ram,
		CPU:    cpu,
		Disk:   disk,
	}

	return c.JSON(200, usage)
}
