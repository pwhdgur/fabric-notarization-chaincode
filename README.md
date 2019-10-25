# fabric-notarization-chaincode

■ 참조 사이트 : https://medium.com/@kctheservant/an-implementation-example-of-notarization-in-hyperledger-fabric-e66fab155fdb

< An Implementation Example of Notarization(공증) in Hyperledger Fabric >

1. Overview
- 공증 블록체인 서비스는 data immutability, transaction audibility, decentralization in DLTs 측면에서 좋은 사례임.
- 소유 증명에 대한 예제입니다. 누군가가 소유 한 문서가 디지털 서명 기술을 사용하여 원장에 기록되어 있음을 보여주는 흐름입니다.

2. Design
2.1 Ownership of a Document by Digital Signature
- 소유권 증명 기술은 일반적인 공개 키 암호화의 디지털 서명 방식
- 디지털 서명 사용에서, 검증 대상 문서는 먼저 고정 길이 (해시 또는 다이제스트라고 함)로 "해시"되고 private key로 암호화됨.

2.2 Overall Flow
- 사용자는 CA에 registered and enrolled 상태여야 함.
- 등록 후 사용자에게 서명 키 (예 : 개인 키)와 인증서 (사용자의 ID, 사용자의 공개 키 및 인증서의 CA 서명이 포함 된 인증서)가 제공되면 wallet에 저장됩니다.
- 문서의 소유권 기록 : 사용자의 개인 키를 사용하여 문서 해시 및 서명을 계산 후 패브릭 네트워크 원장에 문서 해시를 Key로하여, 제출의 서명 및 타임 스탬프를 기록함.
- 문서의 소유권 확인 : 문서 자체와 작성자의 인증서 필요
                       순서1) 문서의 해시를 계산하고 해시를 기반으로 원장에서 레코드를 검색
					   순서2) 레코드 검색이되면 서명 및 타임 스탬프 검색
					   순서3) 인증서에서 지정된 서명과 공개 키를 사용하여 유효성 검사를 수행
					   
3. Application 

3.1 Chaincode
- 원장과의 상호 작용
- fabcar 예제의 체인 코드를 참조해서 응용
3.1.1 Data Structure in Ledger
- 사용자가 제출 한 문서의 서명과 타임 스탬프를 유지하는 것에 한정된 서비스

// Example Code
type DocRecord struct {
 Signature   string `json:"signature"`
 Time  string `json:"time"`
}

3.1.2 Chaincode Functions
- not define the Init()
- Invoke()안에 queryDocRecord() and createDocRecord() 정의

// Example Code : Init()
func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

// Example Code : Invoke() { queryDocRecord(), createDocRecord() }

func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {

	 // Retrieve the requested Smart Contract function and arguments
	 function, args := APIstub.GetFunctionAndParameters()
	 
	 // Route to the appropriate handler function to interact with the ledger appropriately
	 if function == "queryDocRecord" {
		return s.queryDocRecord(APIstub, args)
	 } 
	 else if function == "createDocRecord" {
		return s.createDocRecord(APIstub, args)
	 }
 
	return shim.Error("Invalid Smart Contract function name.")
}

3.1.3 createDocRecord()
- 매개 변수(2개) : 문서의 해시, 소유자에 의해 서명된 문서
- 원장에 기록[key : value] : key => hash , Value => The document signature and timestamp

// Example Code : createDocRecord()
func (s *SmartContract) createDocRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 2 {
	  return shim.Error("Incorrect number of arguments. Expecting 2")
	 }
	 
	var docrecord = DocRecord{Signature: args[1], Time: time.Now().Format(time.RFC3339)}
	docrecordAsBytes, _ := json.Marshal(docrecord)
	APIstub.PutState(args[0], docrecordAsBytes)
	
	return shim.Success(nil)
}

3.1.4 queryDocRecord()
- 매개 변수(1개) : 문서의 해시
- 원장의 레코드 검색이 목적

// Example Code : queryDocRecord()
func (s *SmartContract) queryDocRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 1 {
	  return shim.Error("Incorrect number of arguments. Expecting 1")
	}
	
	docrecordAsBytes, _ := APIstub.GetState(args[0])
	if docrecordAsBytes == nil {
	  return shim.Error("Document not found: " + args[0])
	}
	return shim.Success(docrecordAsBytes)
}

3.2 Client Application
- 클라이언트 4개의 어플리케이션

3.2.1 enrollAdmin.js
- 수정없이 fabcar 예제 사용
- 목적 : CA에 관리자를 등록 후 관리자가 사용자를 등록함
- docrec / wallet 디렉토리 안에 Fabric CA에서 발행 한 서명 키와 X509 인증서가 생성됨.

3.2.2 cli command
$ node enrollAdmin.js

3.2.2 registerUser.js
- fabcar 예제를 수정해서 사용

3.2.2.1 cli command
$ node registerUser.js <username>
// examples
$ node registerUser.js alice
$ node registerUser.js bob

3.2.3 addDocByFile.js
- 목적 : 문서를 기록하는 것
- 입력 매개 변수 user(사용자) : 사용자 지갑에서 서명 키 검색 후 지정된 파일의 해시에 Siganture를 생성
- 입력 매개 변수 FileName : 해시 (SHA-256)가 계산된 기록 할 파일
- 해시 계산 후 createDocRecord() 호출 (필요한 정보 : 파일 해시, 사용자의 해시 서명)

3.2.3.1 cli command
$ node addDocByFile.js <user> <filename>
// example
$ node addDocByFile.js alice alicefile
$ node addDocByFile.js bob bobfile

3.2.4 validateDocByFile.js
- 목적 : 공증 응용 프로그램에서 문서의 유효성 검사

3.2.4.1 전제 조건
- 문서가 이전에 원장에 기록되야함.
- 서명이 정확하고 제공된 인증서로 작성.
- 제공된 인증서는 CA에서 유효한 인증서야함.
- 레코드가 생성 된 시간이 있어야함.

3.2.4.2 입력 매개 변수
- user : 유효한 지갑을 가진 사람,
- filename : 유효성을 검사 할 파일
- usercert : 파일 소유자의 X509 인증서

3.2.4.3 cli command
$ node addDocByFile.js <any_user> <filename> <usercert>
// example
$ node validateDocByFile.js alice alicefile alicecert
$ node validateDocByFile.js admin bobfile bobcert

4. Codes

4.1 chaincode : docrec.go
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
)

type SmartContract struct {
}

// Define the DocRecord Structure, which holds the signature of the document
// signed by issuer, and the time when this record is created
type DocRecord struct {
	Signature   string `json:"signature"`
	Time  string `json:"time"`
}

func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {

	// Retrieve the requested Smart Contract function and arguments
	function, args := APIstub.GetFunctionAndParameters()
	// Route to the appropriate handler function to interact with the ledger appropriately
	if function == "queryDocRecord" {
		return s.queryDocRecord(APIstub, args)
	} else if function == "createDocRecord" {
		return s.createDocRecord(APIstub, args)
	} 

	return shim.Error("Invalid Smart Contract function name.")
}

func (s *SmartContract) queryDocRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	docrecordAsBytes, _ := APIstub.GetState(args[0])

	if docrecordAsBytes == nil {
		return shim.Error("Document not found: " + args[0])
	}

	return shim.Success(docrecordAsBytes)
}

func (s *SmartContract) createDocRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	var docrecord = DocRecord{Signature: args[1], Time: time.Now().Format(time.RFC3339)}
	docrecordAsBytes, _ := json.Marshal(docrecord)
	APIstub.PutState(args[0], docrecordAsBytes)

	return shim.Success(nil)
}

func main() {

	// Create a new Smart Contract
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}
}

4.2 enrollAdmin.js

/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const FabricCAServices = require('fabric-ca-client');
const { FileSystemWallet, X509WalletMixin } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const ccpPath = path.resolve(__dirname, '..', 'basic-network', 'connection.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

async function main() {
    try {

        // Create a new CA client for interacting with the CA.
        const caURL = ccp.certificateAuthorities['ca.example.com'].url;
        const ca = new FabricCAServices(caURL);

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the admin user.
        const adminExists = await wallet.exists('admin');
        if (adminExists) {
            console.log('An identity for the admin user "admin" already exists in the wallet');
            return;
        }

        // Enroll the admin user, and import the new identity into the wallet.
        const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
        const identity = X509WalletMixin.createIdentity('Org1MSP', enrollment.certificate, enrollment.key.toBytes());
        wallet.import('admin', identity);
        console.log('Successfully enrolled admin user "admin" and imported it into the wallet');

    } catch (error) {
        console.error(`Failed to enroll admin user "admin": ${error}`);
        process.exit(1);
    }
}

main();

4.3 registerUser.js

/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { FileSystemWallet, Gateway, X509WalletMixin } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const ccpPath = path.resolve(__dirname, '..', 'basic-network', 'connection.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

async function main() {
    try {

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        const user = process.argv[2];

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(user);
        if (userExists) {
            console.log('An identity for the user ' + user + ' already exists in the wallet');
            return;
        }

        // Check to see if we've already enrolled the admin user.
        const adminExists = await wallet.exists('admin');
        if (!adminExists) {
            console.log('An identity for the admin user "admin" does not exist in the wallet');
            console.log('Run the enrollAdmin.js application before retrying');
            return;
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: 'admin', discovery: { enabled: false } });

        // Get the CA client object from the gateway for interacting with the CA.
        const ca = gateway.getClient().getCertificateAuthority();
        const adminIdentity = gateway.getCurrentIdentity();

        // Register the user, enroll the user, and import the new identity into the wallet.
        const secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: user, role: 'client' }, adminIdentity);
        const enrollment = await ca.enroll({ enrollmentID: user, enrollmentSecret: secret });
        const userIdentity = X509WalletMixin.createIdentity('Org1MSP', enrollment.certificate, enrollment.key.toBytes());
        wallet.import(process.argv[2], userIdentity);
        console.log('Successfully registered and enrolled user ' + user + ' and imported it into the wallet');

    } catch (error) {
        console.error(`Failed to register user: ${error}`);
        process.exit(1);
    }
}

main();

4.4 addDocByFile.js
'use strict';

const { FileSystemWallet, Gateway } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const { KJUR, KEYUTIL } = require('jsrsasign');
const CryptoJS = require('crypto-js');

const ccpPath = path.resolve(__dirname, '..', 'basic-network', 'connection.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

async function main() {
    try {

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);

        // Collect input parameters
        // user: who initiates this query, can be anyone in the wallet
        // filename: the file to be validated
        const user = process.argv[2];
        const filename = process.argv[3];

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(user);
        if (!userExists) {
            console.log('An identity for the user ' + user + ' does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }

        // calculate Hash from the specified file
        const fileLoaded = fs.readFileSync(filename, 'utf8');
        var hashToAction = CryptoJS.SHA256(fileLoaded).toString();
        console.log("Hash of the file: " + hashToAction);

        // extract certificate info from wallet

        const walletContents = await wallet.export(user);
        const userPrivateKey = walletContents.privateKey;

        var sig = new KJUR.crypto.Signature({"alg": "SHA256withECDSA"});
        sig.init(userPrivateKey, "");
        sig.updateHex(hashToAction);
        var sigValueHex = sig.sign();
        var sigValueBase64 = new Buffer(sigValueHex, 'hex').toString('base64');
        console.log("Signature: " + sigValueBase64);

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: user, discovery: { enabled: false } });

        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');

        // Get the contract from the network.
        const contract = network.getContract('docrec');

        // Submit the specified transaction.
        await contract.submitTransaction('createDocRecord', hashToAction, sigValueBase64);
        console.log('Transaction has been submitted');

        // Disconnect from the gateway.
        await gateway.disconnect();

    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        process.exit(1);
    }
}

main();

4.5 validateDocByFile.js

'use strict';

const { FileSystemWallet, Gateway } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const { KJUR, KEYUTIL, X509 } = require('jsrsasign');
const CryptoJS = require('crypto-js');

const ccpPath = path.resolve(__dirname, '..', 'basic-network', 'connection.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

const caCertPath = path.resolve(__dirname, '..', 'basic-network', 'crypto-config', 'peerOrganizations', 'org1.example.com', 'ca', 'ca.org1.example.com-cert.pem');
const caCert = fs.readFileSync(caCertPath, 'utf8');


async function main() {
    try {

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);

        // Collect input parameters
        // user: who initiates this query, can be anyone in the wallet
        // filename: the file to be validated
        // certfile: the cert file owner who signed the document
        const user = process.argv[2];
        const filename = process.argv[3];
        const certfile = process.argv[4];

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(user);
        if (!userExists) {
            console.log('An identity for the user ' + user + ' does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }

        // calculate Hash from the file
        const fileLoaded = fs.readFileSync(filename, 'utf8');
        var hashToAction = CryptoJS.SHA256(fileLoaded).toString();
        console.log("Hash of the file: " + hashToAction);

        // get certificate from the certfile
        const certLoaded = fs.readFileSync(certfile, 'utf8');

        // retrieve record from ledger

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: user, discovery: { enabled: false } });

        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');

        // Get the contract from the network.
        const contract = network.getContract('docrec');

        // Submit the specified transaction.
        const result = await contract.evaluateTransaction('queryDocRecord', hashToAction);
        console.log("Transaction has been evaluated");
        var resultJSON = JSON.parse(result);
        console.log("Doc record found, created by " + resultJSON.time);
        console.log("");

        // Show info about certificate provided
        const certObj = new X509();
        certObj.readCertPEM(certLoaded);
        console.log("Detail of certificate provided")
        console.log("Subject: " + certObj.getSubjectString());
        console.log("Issuer (CA) Subject: " + certObj.getIssuerString());
        console.log("Valid period: " + certObj.getNotBefore() + " to " + certObj.getNotAfter());
        console.log("CA Signature validation: " + certObj.verifySignature(KEYUTIL.getKey(caCert)));
        console.log("");

        // perform signature checking
        var userPublicKey = KEYUTIL.getKey(certLoaded);
        var recover = new KJUR.crypto.Signature({"alg": "SHA256withECDSA"});
        recover.init(userPublicKey);
        recover.updateHex(hashToAction);
        var getBackSigValueHex = new Buffer(resultJSON.signature, 'base64').toString('hex');
        console.log("Signature verified with certificate provided: " + recover.verify(getBackSigValueHex));

        // perform certificate validation
        // var caPublicKey = KEYUTIL.getKey(caCert);
        // var certValidate = new KJUR.crypto.Signature({"alg": "SHA256withECDSA"});
        // certValidate.init(caPublicKey);
        // certValidate.update

        // Disconnect from the gateway.
        await gateway.disconnect();


    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        process.exit(1);
    }
}

main();

5. Demonstration
- 데모 네트워크 : Basic Network from fabric-samples
- 네트워크 구성 : single-peer, one order, one Fabric CA
- 채널 이름 : mychannel

5.1 프로젝트 디렉토리 생성
# inside fabric-samples
$ mkdir docrec && cd docrec

5.2 필요한 패키지로드
- Fabric SDK 외에도 X509 인증서 및 암호화 처리가 필요

# inside fabric-samples/docrec
$ npm init -y
$ npm install fabric-ca-client fabric-network crypto-js jsrsasign -S

5.3 체인 코드
- 데모 목적으로 체인 코드를 fabric-samples / chaincode 디렉토리에 배치합니다. 이 디렉토리는 기본 네트워크의 실행중인 컨테이너에서 액세스 할 수 있습니다.(셋업 파일내용 참조)

# inside fabric-samples/chaincode
$ mkdir docrec && cd docrec
$ <put the docrec.go file here>

5.4 클라이언트 애플리케이션
- 총 4 개의 클라이언트 응용 프로그램
- fabric-samples / docrec 디렉토리에 생성 (에디터로 작성필요)

# inside fabric-samples/docrec
$ <put the four files enrollAdmin.js, registerUser.js, addDocByFile.js and validateDocByFile.js>

5.5 기본 네트워크 시작
- 5 개의 컨테이너가 모두 실행 중인지 확인
- mychannel 생성되고 피어 노드가 채널에 참여하는지 확인

# inside fabric-samples/basic-network
$ ./start.sh && docker-compose -f docker-compose.yml up -d cli
$ docker ps -a

5.6 docrec 체인 코드 설치 및 인스턴스화
- 기본 네트워크가 시작된 후 체인 코드 설치 및 인스턴스화 작업을 수행함.

# any directory
$ docker exec cli peer chaincode install -n docrec -v 1.0 -p "github.com/docrec"
$ docker exec cli peer chaincode instantiate -o orderer.example.com:7050 -C mychannel -n docrec -v 1.0 -c '{"Args":[]}' -P "OR ('Org1MSP.member')"

5.7 관리자로 등록
# inside fabric-samples/docrec
$ node enrollAdmin.js
$ ls wallet

5.8 사용자 alice 및 bob을 등록
# inside fabric-samples/docrec
$ node registerUser.js alice
$ node registerUser.js bob
$ ls wallet

5.9 Extract Certificate from alice and bob
- 편집기를 사용해서 alicecert 및 bobcert의 두 파일로 보관

# inside fabric-samples/docrec
$ cat wallet/alice/alice
$ cat wallet/bob/bob

5.10 데모 용 파일 두 개 생성
# inside fabric-sample/docrec
$ echo "This is a test file for alice" > alicefile
$ echo "This is another test file for bob" > bobfile

5.11 공증 응용 프로그램에서 파일 추가
# inside fabric-sample/docrec
$ node addDocByFile.js alice alicefile
$ node addDocByFile.js bob bobfile

5.12 공증 응용 프로그램에서 파일의 유효성 확인
- validateDocByFile.js 를 사용 하여 인증서가있는 파일의 유효성을 검사
- validate alicefile with alicecert
- validate bobfile with bobcert

# positive result (true)
# inside fabric-sample/docrec
$ node validateDocByFile.js alice alicefile alicecert
$ node validateDocByFile.js alice bobfile bobcert

# negative result. (false)
# inside fabric-sample/docrec
$ node validateDocByFile.js alice alicefile bobcert
$ node validateDocByFile.js alice bobfile alicecert

- 이전에 제출되지 않은 파일의 유효성을 검사 결과
# inside fabric-sample/docrec
$ echo "File not recorded" > nofile
$ node validateDocByFile.js alice nofile alicecert

5.13 Teardown the Demonstration

6. Final
- 개별 사용자에게 문서의 소유권으로 X509를 사용하여 ID 관리를 활용하는 방법을 간략히 제시함


< 참고 명령어 : Clean Up >
cd /fabric-samples/first-network
./byfn.sh down
docker rm $(docker ps -aq)
docker rmi $(docker images dev-* -q)
docker network prune

< 강제로 삭제시 -f >
docker rm -f ID


