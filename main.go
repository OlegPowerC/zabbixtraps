package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	PowerSNMP "github.com/OlegPowerC/powersnmpv3"
)

const DateFormat = "01-02-06 15:04:01"

const (
	MSG_REPORT = 1
	MSG_TRAP   = 2
	MSG_INFORM = 3
)

type UserData struct {
	Username  string `json:"username"`
	Authproto string `json:"authproto"`
	Privproto string `json:"privproto"`
	Auth      string `json:"auth"`
	Priv      string `json:"priv"`
	IPaddr    string `json:"ipaddr"`
}
type Settings struct {
	Logfile   string     `json:"logfile"`
	Timezone  string     `json:"timezone"`
	Debugmode bool       `json:"debugmode"`
	Users     []UserData `json:"users"`
}

type UserKey struct {
	DeviceIP string
	Usename  string
}
type LogMsg struct {
	datavalid bool
	logrow    string
}

type GlobalDataType struct {
	Userv3Map     map[UserKey]*PowerSNMP.SNMPTrapParameters
	GlobalChannel chan LogMsg
	Debugmode     bool
}

const (
	// SNMPv3 флаги
	msgFlag_Encrypted_Bit     = 1
	msgFlag_Authenticated_Bit = 0
)

// Запись трапа в файл
func LogWriter(ctx context.Context, logfile string, GlobalChannel chan LogMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	var TrapFilePointer *os.File
	var trapfileErr error
	_, err := os.Stat(logfile)
	if !os.IsNotExist(err) {
		TrapFilePointer, trapfileErr = os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY, 0644)
		if trapfileErr != nil {
			panic(any(trapfileErr))
		}
		defer TrapFilePointer.Close()
	} else {
		fmt.Println(err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case Logmessage, ok := <-GlobalChannel:
			if !ok {
				return
			}
			if Logmessage.datavalid {
				if TrapFilePointer != nil {
					_, wrerr := TrapFilePointer.WriteString(Logmessage.logrow)
					if wrerr != nil {
						fmt.Println("Error write log:", wrerr)
					}
				}
			}
		}
	}
}

func PrTrap(addr string, port int, data []byte, Userv3Map map[UserKey]*PowerSNMP.SNMPTrapParameters, GlobalChannel chan LogMsg, DebugMode bool) {
	//Приняли трап или информ, извлекаем из него незашифрованные данные
	SNMPver, SNMPv3User, v3SecData, v3globaldata, PuErr := PowerSNMP.ParseTrapUsername(data)
	if PuErr != nil {
		fmt.Println("Parse error")
	}
	var credentials PowerSNMP.SNMPTrapParameters

	if SNMPver == 3 {
		// SNMPv3: ищем пользователя и параметры аутентификации и шифрования, map
		// Сначала ищем по имени + IP адрес устройства
		if userCreds, found := Userv3Map[UserKey{DeviceIP: addr, Usename: SNMPv3User}]; found {
			//Если нашли, то будем передавать эти данные для дешифровки
			credentials = *userCreds
		} else {
			// Теперь ищем с пустым IP адресом
			if userCreds, found = Userv3Map[UserKey{DeviceIP: "", Usename: SNMPv3User}]; found {
				//Если нашли, то будем передавать эти данные для дешифровки
				credentials = *userCreds
			} else {
				fmt.Printf("Unknown user SNMPv3: %s\n", SNMPv3User)
				return
			}
		}
	} else if SNMPver == 1 {
		credentials.SNMPversion = 2
	} else {
		fmt.Printf("Unsupported SNMP version: %d\n", SNMPver)
		return
	}

	_, pmsgtype, datadec, err := PowerSNMP.ParseTrapWithCredentials(addr, port, data, credentials, 0)

	if err != nil {
		fmt.Printf("Error parsing message: %v\n", err)
		return
	}

	var STBuilder strings.Builder
	for _, gdata := range datadec.VarBinds {
		STBuilder.WriteString(PowerSNMP.Convert_OID_IntArrayToString_RAW(gdata.RSnmpOID))
		STBuilder.WriteString(" = ")
		STBuilder.WriteString(PowerSNMP.Convert_Variable_To_String(gdata.RSnmpVar))
		STBuilder.WriteString(" : ")
		STBuilder.WriteString(PowerSNMP.Convert_ClassTag_to_String(gdata.RSnmpVar))
		STBuilder.WriteString("\n")
	}
	VarBindsStr := STBuilder.String()

	Timelocation, LtimelocErr := time.LoadLocation("Europe/Moscow")
	if LtimelocErr != nil {
		fmt.Println(LtimelocErr)
		Timelocation = time.UTC
	}

	//Готовим текст для записи в файл
	ZabbixDateString := time.Now().In(Timelocation).Format(DateFormat)
	ZabbixLogString := fmt.Sprintf("%s ZBXTRAP %s VARBINDS:\n%s", ZabbixDateString, addr, VarBindsStr)

	if DebugMode {
		DebugPrint(addr, SNMPver, SNMPv3User, pmsgtype, credentials, ZabbixLogString, v3SecData, v3globaldata, datadec)
	}

	//Отправим в канал или отбросим если канал полон
	select {
	case GlobalChannel <- LogMsg{datavalid: true, logrow: ZabbixLogString}:
	default:
		fmt.Println("Channel is full")
	}

}

func RecPacket(ctx context.Context, conn net.PacketConn, Userv3Map map[UserKey]*PowerSNMP.SNMPTrapParameters, GlobalChannel chan LogMsg, DebugMode bool, wg *sync.WaitGroup) {
	defer wg.Done()
	buff := make([]byte, 2048)
	var gracefullshflag atomic.Bool
	gracefullshflag.Store(false)

	go func() {
		<-ctx.Done()
		gracefullshflag.Store(true)
		conn.Close()
	}()

	for {
		n, addr, err := conn.ReadFrom(buff)
		if err != nil {
			if gracefullshflag.Load() {
				return
			}
			fmt.Println("Read error:", err)
			continue
		}
		data := make([]byte, n)
		copy(data, buff[:n])
		udpAddr := addr.(*net.UDPAddr)
		srcIP := udpAddr.IP.String()
		srcPort := udpAddr.Port
		go PrTrap(srcIP, srcPort, data, Userv3Map, GlobalChannel, DebugMode)
	}
}

func main() {
	var SettingsData Settings
	ex, err := os.Executable()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	exPath := filepath.Dir(ex)

	SettingsfileFp := strings.ToLower(fmt.Sprintf("%s/%s.json", exPath, "settings"))

	_, err = os.Stat(SettingsfileFp)
	if !os.IsNotExist(err) {
		SettingsFile, SettingsFileErr := os.Open(SettingsfileFp)
		if SettingsFileErr != nil {
			panic(any(SettingsFileErr))
		}
		defer SettingsFile.Close()
		byteValue, _ := io.ReadAll(SettingsFile)
		umerr := json.Unmarshal(byteValue, &SettingsData)
		if umerr != nil {
			fmt.Println(umerr)
			os.Exit(1)
		}
	} else {
		fmt.Println(err)
		os.Exit(1)
	}

	_, err = os.Stat(SettingsData.Logfile)
	if os.IsNotExist(err) {
		fmt.Println(err)
		os.Exit(1)
	}

	var GlobalData GlobalDataType
	GlobalData.GlobalChannel = make(chan LogMsg, 1000)
	GlobalData.Userv3Map = make(map[UserKey]*PowerSNMP.SNMPTrapParameters)
	GlobalData.Debugmode = SettingsData.Debugmode

	for _, CUser := range SettingsData.Users {
		if len(CUser.Username) == 0 {
			//Если имя пользователя пустое
			fmt.Println("SNMP v3 user is empty")
			continue
		}

		//Проверим допустимые ли протоколы и пароли
		_, _, _, cherr := PowerSNMP.CheckSNMPv3StringParams(CUser.Authproto, CUser.Auth, CUser.Privproto, CUser.Priv)
		if cherr != nil {
			fmt.Println("user:", CUser.Username, cherr)
			continue
		}

		GlobalData.Userv3Map[UserKey{DeviceIP: CUser.IPaddr, Usename: CUser.Username}] = &PowerSNMP.SNMPTrapParameters{Username: CUser.Username,
			AuthProtocol: CUser.Authproto,
			AuthKey:      CUser.Auth,
			PrivProtocol: CUser.Privproto,
			PrivKey:      CUser.Priv}
	}

	fmt.Println("SNMPv3 Users:")
	for k, v := range GlobalData.Userv3Map {
		fmt.Println("User:", k, "Auth protocol:", v.AuthProtocol, "Priv protocol:", v.PrivProtocol)
	}

	conn, err := net.ListenPacket("udp", ":162")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg.Add(1)
	go LogWriter(ctx, SettingsData.Logfile, GlobalData.GlobalChannel, &wg)

	wg.Add(1)
	go RecPacket(ctx, conn, GlobalData.Userv3Map, GlobalData.GlobalChannel, GlobalData.Debugmode, &wg)

	//Ждем сигнал и завершаем все потоки
	ctxsig, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()
	<-ctxsig.Done()
	cancel()

	wg.Wait()
}

func DebugPrint(
	SourceIp string,
	SNMPver int,
	SNMPv3User string,
	pmsgtype int,
	Userdata PowerSNMP.SNMPTrapParameters,
	LogMsg string,
	v3SecData PowerSNMP.SNMPv3_SecSeq,
	v3globaldata PowerSNMP.SNMPv3_GlobalData,
	datadec PowerSNMP.SNMP_Packet_V2_decoded_PDU) {

	SNMPprintver := ""
	msgTypeStr := ""
	ackStatus := ""

	if SNMPver == 3 {
		SNMPprintver = "3"
	} else if SNMPver == 1 {
		SNMPprintver = "2c"
	} else {
		fmt.Printf("Unsupported SNMP version: %d\n", SNMPver)
		return
	}

	switch pmsgtype {
	case MSG_REPORT:
		msgTypeStr = "REPORT"
		ackStatus = ""
	case MSG_TRAP:
		msgTypeStr = "TRAP"
		ackStatus = "(No need ACK)"
	case MSG_INFORM:
		msgTypeStr = "INFORM"
		ackStatus = "(send ACK)"
	default:
		msgTypeStr = fmt.Sprintf("UNKNOWN(%d)", pmsgtype)
		ackStatus = ""
	}

	fmt.Println("----------------------------------------------------------")
	fmt.Println("received trap/inform version:", SNMPprintver, "User/Community", SNMPv3User)
	fmt.Println("Source IP:", SourceIp)
	fmt.Printf("Message Type: %s %s\n", msgTypeStr, ackStatus)
	fmt.Printf("RequestID:    %d\n", datadec.RequestID)
	fmt.Printf("VarBinds:     %d\n", len(datadec.VarBinds))

	if SNMPver == 3 {
		EngineIdHstr := ""
		if len(v3SecData.AuthEng) > 0 {
			EngineIdHstr = hex.EncodeToString(v3SecData.AuthEng)
		}

		fmt.Printf("Boots: %d, Time: %d, EngineID %s\r\n", v3SecData.Boots, v3SecData.Time, EngineIdHstr)
		fmt.Println("Auth protocol:", Userdata.AuthProtocol)
		fmt.Println("Priv protocol:", Userdata.PrivProtocol)
		if len(v3globaldata.MsgFlag) > 0 {
			if v3globaldata.MsgFlag[0]&(1<<msgFlag_Authenticated_Bit) != 0 {
				fmt.Println("Authenticated message")
			} else {
				fmt.Println("Not authenticated message")
			}
			if v3globaldata.MsgFlag[0]&(1<<msgFlag_Encrypted_Bit) != 0 {
				fmt.Println("Encrypted message")
			} else {
				fmt.Println("Unencrypted message")
			}
		}
	}
	fmt.Println("Message to file:", LogMsg)
	fmt.Println("----------------------------------------------------------")
}
