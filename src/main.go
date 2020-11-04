package main

import (
    "bufio"
    "fmt"
    "io"
	"os"
	"strings"
	"encoding/csv"
	"github.com/BurntSushi/toml"
	"flag"
	"time"
	"strconv"
)

type ScenarioLine struct {
	logtype string
	time string
	srcip string
	destip string
	natsrcip string
	natdestip string
	rulename string
	srczone string
	destzone string	
	ininterface string
	outinterface string
	srcport string
	destport string								
	natsrcport string
	natdestport string		
	protocol string		
	action string	
	ser string
	description string	
	
}

type TomlConfig struct {
	Device		DeviceConfig		
}

type DeviceConfig struct {
	Device		string			`toml:"devicename"`
	Interface	[]NetworkConfig	`toml:"interface"`
}

type NetworkConfig struct {
    Ifname	string	 `toml:"ifname"`
	Ip		string	 `toml:"ip"`
	Zone	string	 `toml:"zone"`
	Vlanid	string	 `toml:"vlanid"`	
}

type UnexpectedResult struct {
	No			int	
	Message		string			
}

func main() {
    var (
	 	flgLogFile	= flag.String("f", "", "Specification a log file.")
		flgCfg		= flag.String("c", "config.tml", "Specification a config file.")		
	)
	
	flag.Parse()
	if *flgLogFile == "" {
        fmt.Println("Log file not specified.")
		os.Exit(1)
	}
	
	baseLogData , err := readLine(*flgLogFile)

	if err != nil {
		fmt.Println(err)
        os.Exit(1)
	}
	
	err = genScenario(baseLogData , *flgCfg)

	if err != nil {
		fmt.Println(err)
        os.Exit(1)
	}

}

//logファイルを読み込む
func readLine(filename string) ([]ScenarioLine , error) {
	var logdata []ScenarioLine

    file, err := os.Open(filename)
    if err != nil {
        return logdata , err
    }
    defer file.Close()

    reader := bufio.NewReader(file)

	//logdataMapのindexとして利用
	j := 0
	//ログを1行ごと読み込む
    for {
        line, isPrefix, err := reader.ReadLine()
        if err == io.EOF {
            break
        }
        if err != nil {
       		return logdata , err
        }
		
		// カンマでスプリット
		slice := strings.Split(string(line), ",")

		//CSVフォーマットをチェック
		///ログのコメント除外
		if slice[0] == "##" {
			continue
		//ログの項目数確認
		}else if  len(slice) != 65 {
			fmt.Println("Unexpected a log format.")
			os.Exit(1)
		//ログのヘッダーを除外
		} else if slice[3] != "TRAFFIC" {
			continue
		}

		//スプリットした値を入れるMAPを作成
		logdataLineMap := make(map[string]string)

  		for i, str := range slice {
			switch(i){
				case 3:
					logdataLineMap["logtype"] = str
				case 6:
					logdataLineMap["time"] = str
				case 7:
					logdataLineMap["srcip"] = str
				case 8:
					logdataLineMap["destip"] = str
				case 9:
					logdataLineMap["natsrcip"] = str
				case 10:
					logdataLineMap["natdestip"] = str
				case 11:
					logdataLineMap["rulename"] = str
				case 16:
					logdataLineMap["srczone"] = str
				case 17:
					logdataLineMap["destzone"] = str
				case 18:
					logdataLineMap["ininterface"] = str
				case 19:
					logdataLineMap["outinterface"] = str
				case 24:
					logdataLineMap["srcport"] = str
				case 25:
					logdataLineMap["destport"] = str
				case 26:
					logdataLineMap["natsrcport"] = str
				case 27:
					logdataLineMap["natdestport"] = str
				case 29:
					logdataLineMap["protocol"] = str
				case 30:
					logdataLineMap["action"] = str
				case 46:
					//Session End Reason
					logdataLineMap["ser"] = str					
			}
		}  

    	if isPrefix {
			break
		} 

		//想定しない値があった場合にdescriptionに追記する
		logdataLineMap["description"] = " ,"

		//----値をシナリオ対応用語に変更----
		//Action
		switch(logdataLineMap["action"]){
			case "allow":
				logdataLineMap["action"] = "pass"
			case "deny":
				logdataLineMap["action"] = "drop"
			case "drop":
				logdataLineMap["action"] = "drop"
			case "drop-ICMP":
				logdataLineMap["action"] = "drop"										
			case "reset-both":
				logdataLineMap["action"] = "drop"
			case "reset-client":
				logdataLineMap["action"] = "drop"	
			case "reset-server":
				logdataLineMap["action"] = "drop"										
			default:
				logdataLineMap["description"] += " | exception(action:" + logdataLineMap["action"] + ")"
				logdataLineMap["action"] = "undefined"
		}

		//DestNATIP
		//DestNATしている場合は、宛先と宛先NATIPを入れ替えてシナリオを作成する
		switch{
			case logdataLineMap["natdestip"] ==  "0.0.0.0":
				logdataLineMap["natdestip"] = ""
			case logdataLineMap["natdestip"] != "":
				tmpVar := logdataLineMap["destip"]
				logdataLineMap["destip"] = logdataLineMap["natdestip"]
				logdataLineMap["natdestip"] = tmpVar
				//宛先ポートとNAT宛先ポートの入れ替え
				tmpVar = logdataLineMap["destport"]
				logdataLineMap["destport"] = logdataLineMap["natdestport"]
				logdataLineMap["natdestport"] = tmpVar
		}

		//SrcNATIP
		switch{
			case logdataLineMap["natsrcip"] == "0.0.0.0":
				logdataLineMap["natsrcip"] = ""
		}

		//SrcPort
		switch{
			case logdataLineMap["srcport"] == "0":
				logdataLineMap["srcport"] = ""
		}
		//DestPort
		switch{
			case logdataLineMap["destport"] == "0":
				logdataLineMap["destport"] = ""
		}
		//NatDestPort
		switch{
			case logdataLineMap["natdestport"] == "0":
				logdataLineMap["natdestport"] = ""
		}
		//NatSrcPort
		switch{
			case logdataLineMap["natsrcport"] == "0":
				logdataLineMap["natsrcport"] = ""
		}
		//Protocol
		switch{
			case logdataLineMap["protocol"] == "icmp" || logdataLineMap["protocol"] == "tcp" || logdataLineMap["protocol"] == "udp":
				break
			default:
				logdataLineMap["description"] += " | exception(protocol:" + logdataLineMap["protocol"] + ")"
				logdataLineMap["protocol"] = "undefined"	
		}

		//----End 値をシナリオ対応用語に変更----

		//MAPに入れた値をスライスに代入（e.g: TRAFFIC 172.16.20.238...）
		logdata = append(logdata, ScenarioLine{logdataLineMap["logtype"],logdataLineMap["time"],logdataLineMap["srcip"],logdataLineMap["destip"],logdataLineMap["natsrcip"],logdataLineMap["natdestip"],logdataLineMap["rulename"],logdataLineMap["srczone"],logdataLineMap["destzone"],logdataLineMap["ininterface"],logdataLineMap["outinterface"],logdataLineMap["srcport"],logdataLineMap["destport"],logdataLineMap["natsrcport"],logdataLineMap["natdestport"],logdataLineMap["protocol"],logdataLineMap["action"],logdataLineMap["ser"],logdataLineMap["description"]})

		j =  j + 1

	}

    return logdata , nil
}

func genScenario(baseLogData []ScenarioLine , tomlFile string) error {

	//シナリオに出力しないログを格納
	var unexpectedLogs []UnexpectedResult

	//Tomlファイル読み込み
	var config TomlConfig
	_, err := toml.DecodeFile(tomlFile, &config)
  	if err != nil {
        return err
    }

	//-----------
	//CSVファイルを新規作成
	t := time.Now().Format("20060102150405")
	scenarioFileName := "NEEDLEWORK_Scenario_" + t + ".csv"
	file, err := os.Create(scenarioFileName)

    if err != nil {
        return err
    }
	defer file.Close()
	
	//ファイルの中身を空にする
	err = file.Truncate(0)

    if err != nil {
        return err
	}
	
	writer := csv.NewWriter(file) // utf8

	//CSVファイルを新規作成
	//----End----

	//シナリオヘッダー情報書き込み
	writer.Write([]string{"exclude-list","protocol","src-fw","src-vlan(option)","src-ip","src-port(option)","src-nat-ip(option)","dst-fw","dst-vlan(option)","dst-nat-ip(option)","dst-nat-port (option)","dst-ip","dst-port","url/domain(option)","anti-virus(option)","timeout(option)","try(option)","other-settings(option)","expect","description"})

	//デフォルト値指定
	sfw		:= "Undefined"
	dfw 	:= []string{"Undefined"}
	svlan	:= "0"
	dvlan 	:= "0"
	// description := ""
	//スライスに格納したログを取り出し、シナリオを作成する
	for i, value := range baseLogData {

		//ログのNOと合わせるために+1する
		i ++

		var newDfw	[]string
		skipLog	:= false
		//Tomlファイルに記載したIF情報とログ中のIN/OUT IF情報を比較し、s-fw、d−fwのIPアドレスを割り当てる
		//i := 0
		for _, tomlValue := range config.Device.Interface {
			//fmt.Println(len(value.outinterface) , value.outinterface)
			//fmt.Println(tomlValue.Ifname)
			// v

			switch{
				//宛先IPがFWのインタフェースに設定されているIPの場合は除外する
				case value.destip == tomlValue.Ip:
					unexpectedLogs = append(unexpectedLogs ,  UnexpectedResult{i , "Skip a log - The FW IP address and the Det IP address are duplicated."})
					skipLog = true
					//break
				//送信元IPがFWのインタフェースに設定されているIPの場合は除外する
				case value.srcip == tomlValue.Ip:
					unexpectedLogs = append(unexpectedLogs ,  UnexpectedResult{i , "Skip a log - The FW IP address and the Src IP address are duplicated."})
					skipLog = true
					//break
				//out IFが空 = Dropログの場合の処理（Zoneからs-fw、d−fwのIPアドレスを割り当てる）
				case len(value.outinterface) <= 1:
					if value.destzone == tomlValue.Zone {
						newDfw  = append(newDfw, tomlValue.Ip)
						dvlan = tomlValue.Vlanid
					}
					//当case終了後も継続する
					fallthrough
				case value.ininterface == tomlValue.Ifname:
					sfw = tomlValue.Ip
					svlan = tomlValue.Vlanid
				case value.outinterface == tomlValue.Ifname:
					newDfw  = append(newDfw, tomlValue.Ip)
					dvlan = tomlValue.Vlanid
				default:
			}

			//newDfwに値が入っている場合はdfwに代入する
			//値が入っていない場合は代入しない（dfwの値はUndefinedになる）
			if len(newDfw) != 0 {
				dfw = newDfw
			}
			
		}

		//シナリオの組み立て
		if skipLog == false {
			for _, dfwMulti := range dfw {
				writer.Write([]string{"",value.protocol , sfw , svlan , value.srcip , value.srcport , value.natsrcip , dfwMulti , dvlan , value.natdestip , value.natdestport , value.destip , value.destport, "" , "" , "", "" , "" , value.action , value.rulename + " | " + value.time , value.description})     
			}
		}
	}
	
	//CSV（シナリオ）書き込み
	writer.Flush() 

	//-----------
	//テキストファイル（実行結果）を新規作成
	resultFilename := "result_" + t + ".txt"
	resultFile, err := os.Create(resultFilename)

    if err != nil {
        return err
    }
	defer resultFile.Close()
	
	//ファイルの中身を空にする
	err = resultFile.Truncate(0)

    if err != nil {
        return err
	}
	
	resultFileWriter := bufio.NewWriter(resultFile) 

	for _, wr := range unexpectedLogs {
		writeString  :=  "no " + strconv.Itoa(wr.No)  + ": " + wr.Message + "\n"

		_, err = resultFileWriter.WriteString(writeString)

		if err != nil {
			return err
		}
	
	}

	resultFileWriter.Flush()
	
	//テキストファイル（実行結果）を新規作成
	//----End----

	fmt.Println("Exported the following files." + "\n")
	fmt.Println("- " + scenarioFileName)
	fmt.Println("- " + resultFilename)

	return nil
}