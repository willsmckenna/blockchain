/*------------------------------------------------------------------------------

    Blockchain.java     Wills Mckenna     May 25th, 2020

    - Java version used: java version "13.0.2" 2020-01-14

    - compile/run instructions:
      > javac -cp "jaxb-api-2.4.0-b180830.0359.jar;gson-2.8.2.jar" Blockchain.java
      > java -cp ".;jaxb-api-2.4.0-b180830.0359.jar;gson-2.8.2.jar" Blockchain <0, 1, 2>

    - Files needed to run:
      Blockchain.java
      BlockInput0.txt, BlockInput1.txt, BlockInput2.txt, or any other text file in proper format

    -Notes: 

    A Blockchain implementation with public/private key verification, JSON usage, and real work. Part of 
    Clark Elliott's CS435 class at Depaul University. Ample help from utility code by Clark Elliott and
    his below referenced web sources.

    The Clark Elliott programs:
    BlockJ.java
    WorkB.java
    bc.java
    BlockInputG.java

    The web sources Elliott used:
    
    https://mkyong.com/java/how-to-parse-json-with-gson/
    http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
    https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
    https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
    https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
    https://www.mkyong.com/java/java-sha-hashing-example/
    https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
    https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
    http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
    https://beginnersbook.com/2013/12/linkedlist-in-java-with-example/
    https://www.javacodegeeks.com/2013/07/java-priority-queue-priorityqueue-example.html

    https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  @author JJ
    https://dzone.com/articles/generate-random-alpha-numeric  by Kunal Bhatia  �  Aug. 09, 12 � Java Zone
    http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example

    Uses GSON Jar- gson-2.8.2.jar

    And if using Java 1.9 or higher, uses XML jar- jaxb-api-2.4.0-b180830.0359.jar

    Program currently lists blocks and credits at end, but does not verify full blockchain again

-----------------------------------------------------------------------------------------------------*/
//utils for the JAR files
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import javax.xml.bind.DatatypeConverter;

//other utils
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.FileReader;
import java.io.Reader;
import java.util.LinkedList;
import java.util.*;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.io.StringReader;
import java.io.BufferedReader;
import java.text.*;

/*-------------------------------------------------------------------------------------------------
    THE PORT CLASS
    ports are configured here
--------------------------------------------------------------------------------------------------*/
class Ports{
    // the port bases and vars
   public static int StartServerBase = 4600;
   public static int PublicKeyServerBase = 4710;
   public static int UnverifiedBlockServerBase = 4820;
   public static int BlockchainServerBase = 4930;
   
   public static int StartServerPort;
   public static int UnverifiedBlockServerPort;
   public static int BlockchainServerPort;
   public static int PublicKeyServerPort;

    public void setPorts(){
      //change port number by 1000 from the base for each process that comes in
      StartServerPort = StartServerBase + (Blockchain.PID * 1000);
      PublicKeyServerPort = PublicKeyServerBase + (Blockchain.PID * 1000);
      UnverifiedBlockServerPort = UnverifiedBlockServerBase + (Blockchain.PID * 1000);
      BlockchainServerPort = BlockchainServerBase + (Blockchain.PID * 1000);
    }
  }

/*-------------------------------------------------------------------------------------------------
    THE DATA CLASSES
    the block unit of a blockchain as a java object, the public key object
--------------------------------------------------------------------------------------------------*/
class BlockRecord{
  //block fields that correspond to the data items of the text files
  String BlockID;
  String TimeStamp;
  //which number of block is it in the blockchain
  int BlockNum;
  //whatever process the block came from
  String VerificationProcessID;
  //the last block's winning hash
  String PreviousHash; 
  //the signed ID
  String SignedID; 
  //the actual data
  String Fname;
  String Lname;
  String SSNum;
  String DOB;
  //the random guess the will be part of the work
  String RandomSeed; 
  //the winning hash of this block
  String WinningHash;
  //the winning hash signed
  String signedWinningHash;
  //more data
  String Diag;
  String Treat;
  String Rx;

  // the getters and setters for above data fields
  public int getBlockNum() {return BlockNum;}
  public void setBlockNum(int num){this.BlockNum = num;}
  
  public String getBlockID() {return BlockID;}
  public void setBlockID(String BID){this.BlockID = BID;}

  public String getTimeStamp() {return TimeStamp;}
  public void setTimeStamp(String TS){this.TimeStamp = TS;}

  public String getVerificationProcessID() {return VerificationProcessID;}
  public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
  
  public String getPreviousHash() {return this.PreviousHash;}
  public void setPreviousHash (String PH){this.PreviousHash = PH;}
  
  public String getSignedID() {return SignedID;} 
  public void setSignedID (String sid){this.SignedID = sid;}

  public String getLname() {return Lname;}
  public void setLname (String LN){this.Lname = LN;}
  
  public String getFname() {return Fname;}
  public void setFname (String FN){this.Fname = FN;}
  
  public String getSSNum() {return SSNum;}
  public void setSSNum (String SS){this.SSNum = SS;}
  
  public String getDOB() {return DOB;}
  public void setDOB (String RS){this.DOB = RS;}

  public String getDiag() {return Diag;}
  public void setDiag (String D){this.Diag = D;}

  public String getTreat() {return Treat;}
  public void setTreat (String Tr){this.Treat = Tr;}

  public String getRx() {return Rx;}
  public void setRx (String Rx){this.Rx = Rx;}

  public String getRandomSeed() {return RandomSeed;}
  public void setRandomSeed (String RS){this.RandomSeed = RS;}
  
  public String getWinningHash() {return WinningHash;}
  public void setWinningHash (String WH){this.WinningHash = WH;}

  public String getSignedWinningHash() {return signedWinningHash;}
  public void setSignedWinningHash (String SWH){this.signedWinningHash = SWH;}

}
//public key object class for storing and marshaling public keys
class PublicKeyObj {
    String publicKey;
    int processID;

    public String getPublicKey(){return this.publicKey;}
    public void setPublicKey(String pk){this.publicKey = pk;}

    public int getProcessID(){return this.processID;}
    public void setProcessID(int id){this.processID = id;}
}
/*-------------------------------------------------------------------------------------------------
    THE SERVER CLASSES
    for the start message, the unverified blocks, the blockchain, and the public keys
--------------------------------------------------------------------------------------------------*/

 //The class that does the work of taking a connection from a possible multicasted process and storing its
 //public key
  class PubKeyWorker extends Thread {
    Socket sock;
    //constructor, assigning incoming conection to a local var
    public PubKeyWorker(Socket s){
      this.sock = s;
    }
    public void run(){
      Gson gson = new Gson();
      try{
        //getting the input stream 
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        //Storing the incoming JSON to the array
        //check if the incoming JSON hasn't already been stored
        //read the incoming JSON string
        String JSON = in.readLine();
        //convert it back to a java object
        PublicKeyObj pk = gson.fromJson(JSON, PublicKeyObj.class);
        //store that object in global array
        Blockchain.pkArray.add(pk);
      }catch(IOException e){System.out.print(e);}
    }
  }

  //Simple server that waits for incoming public keys from other processes
  class PubKeyServer implements Runnable {
    //initialize sockets and q_len as per socket protocol
    int q_len = 6;
    Socket sock;
    //run method for this server
    public void run(){
      try{
        //setting up the listener
        ServerSocket servsock = new ServerSocket(Ports.PublicKeyServerPort, q_len);
        //wait for an incoming message from another process and printing hello
        while (true) {
          //wait for connection, put the connection in sock var
          sock = servsock.accept();
          //spawn off a Public Key worker to do the work of displaying to the console
          new PubKeyWorker(sock).start(); 
        }
      }catch(IOException e){System.out.print("unable to connect...");}
    }
  }
//the worker for the unverified block server
class UnverifiedBlockWorker extends Thread {
    Socket sock;
    //constructor, assigning incoming conection to a local var
    public UnverifiedBlockWorker(Socket s){
      this.sock = s;
    }
    public void run(){
      Gson gson = new Gson();
      try{
        //getting the input stream 
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        //Storing the incoming JSON to the array
        //read the incoming JSON string
        String JSON = in.readLine();
        //convert it back to a java object, in this case an array of blocks, i.e blockchain
        BlockRecord blockRecordData = gson.fromJson(JSON, BlockRecord.class);
        //add the Block into this processes Priority Queue
        Blockchain.blockPriorityQueue.add(blockRecordData);
      }catch(IOException e){System.out.print(e);}
    }
  }
//Server that listens to incoming unverified Blocks
class UnverifiedBlockServer implements Runnable {
    //initialize sockets and q_len as per socket protocol
    int q_len = 6;
    Socket sock;
    //run method for this server
    public void run(){
      try{
        //setting up the listener at the port relative to this process
        ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
        //wait for an incoming message from another process to receive the block
        while (true) {
          //wait for connection, put the connection in sock var
          sock = servsock.accept();
          //spawn off a unverified block worker to process the block
          new UnverifiedBlockWorker(sock).start(); 
        }
      }catch(IOException e){System.out.print("unable to connect...");}
    }
  }
  //this class does the work of reading an incoming blockchain
  class BlockchainWorker extends Thread {
    Socket sock;
    //constructor, assigning incoming conection to a local var
    public BlockchainWorker(Socket s){
      this.sock = s;
    }
    public void run(){
      Gson gson = new Gson();
      try{
        //getting the input stream 
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        //read the incoming JSON string
        String JSON = in.readLine();
        //convert it back to a java object, in this case an array of blocks, i.e blockchain
        BlockRecord[] blockRecordData = gson.fromJson(JSON, BlockRecord[].class);
        //store the new blockchain as the global variable blockchain
        //empty it first
        Blockchain.blockChain.clear();
        //then add all the blocks
        for (BlockRecord block: blockRecordData){
          Blockchain.blockChain.add(block);
        }
        //every time there is an update that process 0 hears, it re-writes it to file
        if (Blockchain.PID == 0){
          Blockchain.writeToFile(Blockchain.blockChain);
        }
      }catch(IOException e){System.out.print(e);}
    }
  }


  //Server that listens to incoming blockchains
  class BlockchainServer implements Runnable {
    //initialize sockets and q_len as per socket protocol
    int q_len = 6;
    Socket sock;
    //run method for this server
    public void run(){
      try{
        //setting up the listener
        ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
        //wait for an incoming blockchain message
        while (true) {
          //wait for connection, put the connection in sock var
          sock = servsock.accept();
          //spawn off a block chain worker 
          new BlockchainWorker(sock).start(); 
        }
      }catch(IOException e){System.out.print("unable to connect...");}
    }
  }
  //accepts the start message and passes it to a global variable
  class StartWorker extends Thread {
    Socket sock;
    //constructor, assigning incoming conection to a local var
    public StartWorker(Socket s){
      this.sock = s;
    }
    public void run(){
      try{
        //getting the input stream 
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        //storing the start message in the global start variable
        Blockchain.start = in.readLine();
        
      }catch(IOException e){System.out.print(e);}
    }
  }
  //the server that listens to the start message from process 2
  class StartServer implements Runnable {
    //initialize sockets and q_len as per socket protocol
    int q_len = 6;
    Socket sock;
    //run method for this server
    public void run(){
      try{
        //setting up the listener
        ServerSocket servsock = new ServerSocket(Ports.StartServerPort, q_len);
        //wait for an incoming message from another process 
        while (true) {
          //wait for connection, put the connection in sock var
          sock = servsock.accept();
          //spawn off the thread that reads the start message
          new StartWorker(sock).start(); 
        }
      }catch(IOException e){System.out.print("unable to connect...");}
    }
  }
/*-------------------------------------------------------------------------------------------------
    BLOCKCHAIN MAIN CLASS
    with helper functions (including security, work method and JSON reading/multicasting) and main()
--------------------------------------------------------------------------------------------------*/
public class Blockchain {
    static String serverName = "localhost";
    static int numProcesses = 3; // needs to be 3 total processes
    static int PID = 0; // initialize the process id
    //the Unverified block array relative to this process
    static List<BlockRecord> blockArr = new ArrayList<BlockRecord>();
    //global var for the name of the file that will be read
    private static String FILENAME;
    //the global string used for creating the random seed
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    //the global blockchain, that will be changed as the processes verify blocks and send off the 
    //the newly prepended blockchains
    public static LinkedList<BlockRecord> blockChain = new LinkedList<>();
    //the public key array, where all the processes public keys will be stored
    public static List<PublicKeyObj> pkArray = new ArrayList<>();
    //this processes private key
    public static PrivateKey privKey;
    //the start message, wait for it to say go
    public static String start = "wait";
    //the indexes for getting the data items in the text file
    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;

     //the comparator method from Clark Elliott's InputBlockG.java. Returns a comparator that runs 
    //between two block objects. returns 0 if the two block's time stamps are the same, -1 or 1 if 
    //one of the blocks do not have a time stamp; otherwise it runs the compare method on the 
    //two timestamps and orders them from earliest to latest date.   
    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>()
    {
    //overriding the standard object compare method to have the unique implementation
     @Override
     public int compare(BlockRecord b1, BlockRecord b2)
     {
      //getting the timestamps of each block
      String s1 = b1.getTimeStamp();
      String s2 = b2.getTimeStamp();
      //return 0 if same
      if (s1 == s2) {return 0;}
      //return 1 or -1 if one of the blocks is null
      if (s1 == null) {return -1;}
      if (s2 == null) {return 1;}
      //otherwise, run the standard compare method but on the timestamps of the blocks in question
      return s1.compareTo(s2);
     }
    };

    //the global priority queue for this process, where we will add the blocks
    static Queue<BlockRecord> blockPriorityQueue = new PriorityQueue<>(4, BlockTSComparator);

    //the hashing procedure mainly from Clark Elliott's BlokJ.java, used on the dummy block 0
    public static String hashBlock(String blockContents){
        //starting off with a blank hash string
        String SHA256String = "";

        try{
            //using MessageDigest class with SHA-256 algorithm to set up and complete the hash 
            MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
            ourMD.update (blockContents.getBytes());
            byte byteData[] = ourMD.digest();

            // Taking the hashed bytes and converting it to Hex. Accord to Clark Elliott this is 
            //not verified code
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
            SHA256String = sb.toString(); // representing this hex value as a string format

        } catch(NoSuchAlgorithmException x){};
        
        // return the string, and this will be the winning string that will then go on to 
        // the next block 
        return SHA256String.toUpperCase(); 

    }

    //initialize the blockchain with a dummy block 0, this will be the same across all 
    //the processes
    public static LinkedList<BlockRecord> initBlockChain(){
        LinkedList<BlockRecord> bc = new LinkedList<>();
        //the dummy block 0
        BlockRecord block0 = new BlockRecord();
        //creating the UUID, from the java library, converting it to a string
        String suuid = new String(UUID.randomUUID().toString());
        block0.setBlockID(suuid);
        block0.setBlockNum(0); 
        // the time stamp, sleep so that they are slightly different
        try{Thread.sleep(1001);}catch(InterruptedException e){}
        Date date = new Date();
        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
        String TimeStampString = T1 + "." + Blockchain.PID; 
        //setting the time stamp to the particular block
        block0.setTimeStamp(TimeStampString); 
        block0.setVerificationProcessID("0");
        block0.setPreviousHash("0000000000000000000000000000000000000000000000000000000000000000");
        block0.setFname("Wills"); block0.setLname("Mckenna"); block0.setDOB("09-22-1989");
        block0.setSSNum("123-45-6789"); block0.setDiag("Blockchain euphoria"); 
        block0.setRx("Blockchain pills");
        block0.setTreat("Writing more block chain code");
        block0.setRandomSeed("08L920RE");
        String blockData = concat(block0) + "08L920RE"; 
        block0.setWinningHash(hashBlock(blockData));
        //add block to the blockchain
        bc.add(block0);
        return bc;
    }
    //read file method, creates the other unverified blocks from reading from the files in question and converts them to
    //java objects
    public static List<BlockRecord> readFile(int pid) throws Exception {
        List<BlockRecord> recordList = new ArrayList<>();

        //getting the correct file depending on the process number
        switch(pid){
            case 1: FILENAME = "BlockInput1.txt"; break;
            case 2: FILENAME = "BlockInput2.txt"; break;
            default: FILENAME= "BlockInput0.txt"; break;
        }

        System.out.println("Using input file: " + FILENAME);
        //here we go through the file, putting its data items into an unverified block
        try {
        BufferedReader br = new BufferedReader(new FileReader(FILENAME));
        //the tokens for breaking up the text file's data
        String[] tokens = new String[10];
        String InputLineStr;
        String suuid;
        UUID idA;
        BlockRecord tempRec;
        
        StringWriter sw = new StringWriter();
        //for number of records read
        int n = 0;
        
        while ((InputLineStr = br.readLine()) != null) {
            //each line is a new block
            BlockRecord BR = new BlockRecord(); 
            // the time stamp, sleep so that they are slightly different
            try{Thread.sleep(1001);}catch(InterruptedException e){}
            Date date = new Date();
            String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
            String TimeStampString = T1 + "." + pid; 
            //setting the time stamp to the particular block
            BR.setTimeStamp(TimeStampString); 
            BR.setBlockNum(n);
            
            //creating the UUID, from the java library, converting it to a string
            suuid = new String(UUID.randomUUID().toString());
            BR.setBlockID(suuid);
            //sign the ID with this processes private key, for verification once in the priority queue
            byte[] digitalSignature = signData(suuid.getBytes(), privKey);
            String SignedSHA256ID = Base64.getEncoder().encodeToString(digitalSignature);
            //set it as the signed ID
            BR.setSignedID(SignedSHA256ID);
            //splitting up the text file and setting the data items
            tokens = InputLineStr.split(" +"); 
            BR.setFname(tokens[iFNAME]);
            BR.setLname(tokens[iLNAME]);
            BR.setSSNum(tokens[iSSNUM]);
            BR.setDOB(tokens[iDOB]);
            BR.setDiag(tokens[iDIAG]);
            BR.setTreat(tokens[iTREAT]);
            BR.setRx(tokens[iRX]);
            BR.setVerificationProcessID(Integer.toString(Blockchain.PID));
            //adding the block to the list of UBs of this process
            recordList.add(BR);
            //upping the number of blocks read
            n++;
        }
        } catch (Exception e){System.out.println(e);}

        return recordList;
    }
    // initializing this processes' public key
    public static PublicKeyObj initPublicKey(int pid) throws Exception {
        //generate key pair for this process, use random number generator class
        Random rand = new Random();
        long randomNum = rand.nextInt(1000);
        KeyPair keyPair = generateKeyPair(randomNum);
        //store privatekey in this process's global var for privatekey
        privKey = keyPair.getPrivate();
        //create the public key
        //getting the public key from the pair, first in byte form then translating it to string
        byte[] bytePubkey = keyPair.getPublic().getEncoded();
        //System.out.println("Key in Byte[] form: " + bytePubkey);
        //using Base64 to represent the bytes of the key as a string
        String stringKey = Base64.getEncoder().encodeToString(bytePubkey);
        //System.out.println("Key in String form: " + stringKey);
        //set up the public key object
        PublicKeyObj pk = new PublicKeyObj(); 
        pk.setPublicKey(stringKey); pk.setProcessID(pid);
        //return the public key/process num as an object
        return pk;
      }
      // the helper method from BlokJ.java that generates the key pair for signage and encryption/decryption
    public static KeyPair generateKeyPair(long seed) throws Exception {
        //initializing the key pair with RSA algorithm 
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        //sets up the random generator with SHA1PRNG algorithm
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        //randomizes the seed 
        rng.setSeed(seed);
        //creates the key pair of size 1024 with the random seed rng
        keyGenerator.initialize(1024, rng);
        
        return (keyGenerator.generateKeyPair());
    }
    //signData method from BlokJ.java, takes the data and uses private key to sign it
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        //gets the algorithm 
        Signature signer = Signature.getInstance("SHA1withRSA");
        //initializes the signature with the private key put in the method call
        signer.initSign(key);
        //updates the data in byte form, getting it ready for signing
        signer.update(data);
        //signs the data 
        return (signer.sign());
    }
    // verifySig method from BlokJ.java, this uses the public key to to see if the signature is valid
    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        //sets up the correct algorithm
        Signature signer = Signature.getInstance("SHA1withRSA");
        //initializes the signer object with the correct public key
        signer.initVerify(key);
        //gets data ready to be verified
        signer.update(data);
        //returns whether or not the the digital signature was signed with a private key that matches 
        //the supplied public key
        return (signer.verify(sig));
    }
    //the multisend method for sending the public key message to one or more processes
    public void MultiSendPK(PublicKeyObj pk) throws Exception {
        Socket sock;
        PrintStream toServer;
        Gson gson = new GsonBuilder().create();

        // take the pub key obj and change it into a JSON object
        String JSON = gson.toJson(pk);
        try{
            //loop 3 times for each process
          for(int i=0; i< numProcesses; i++){
            //create a new connection to each port, port num spaced out 1000 apart
            sock = new Socket(serverName, Ports.PublicKeyServerBase + (i * 1000));
            //set up the output stream to the receiving server
            toServer = new PrintStream(sock.getOutputStream());
            //send the message, the public key and process num in JSON format
            toServer.println(JSON); toServer.flush();
          } 
        }catch (Exception x) {x.printStackTrace ();}
      }
    //the multisend method for sending the go message from process 2
    public void MultiSendStart() throws Exception {
      Socket sock;
      PrintStream toServer;
      try{
          //loop 3 times for each process
        for(int i=0; i< numProcesses; i++){
          //create a new connection to each port, port num spaced out 1000 apart
          sock = new Socket(serverName, Ports.StartServerBase + (i * 1000));
          //set up the output stream to the receiving server
          toServer = new PrintStream(sock.getOutputStream());
          //send the message, a simple string indicating start
          toServer.println("go"); toServer.flush();
        } 
      }catch (Exception x) {x.printStackTrace ();}
    }
    //the multisend method for sending the JSON formatted Unverified Block. Multicasts
    //only one block, so need to loop through the other UBs in the process's UB list
    public void MultiSendUB(BlockRecord block, int ServerBase) throws Exception {
        Socket sock;
        PrintStream toServer;

        try{
            Gson gson = new GsonBuilder().create();
            // take the block record object and change it into a JSON object
            String JSON = gson.toJson(block);
            //loop 3 times for each process
          for(int i=0; i< numProcesses; i++){
            //create a new connection to each port, port num spaced out 1000 apart
            sock = new Socket(serverName, ServerBase + (i * 1000));
            //set up the output stream to the receiving server
            toServer = new PrintStream(sock.getOutputStream());
            //send the message with this process's ID num
            toServer.println(JSON); toServer.flush();
          } 
        
        }catch (Exception x) {x.printStackTrace ();}
    }
    //the multisend method for sending the JSON formatted blockchain
    public void MultiSendBC(LinkedList<BlockRecord>bc, int ServerBase) throws Exception {
      Socket sock;
      PrintStream toServer;

      try{
          Gson gson = new GsonBuilder().create();
          // take the block record object and change it into a JSON object using helper method
          String JSON = convertBCToJson(bc);
          //loop 3 times for each process
        for(int i=0; i< numProcesses; i++){
          //create a new connection to each port, port num spaced out 1000 apart
          sock = new Socket(serverName, ServerBase + (i * 1000));
          //set up the output stream to the receiving server
          toServer = new PrintStream(sock.getOutputStream());
          //send the message 
          toServer.println(JSON); toServer.flush();
        } 
      
      }catch (Exception x) {x.printStackTrace ();}
  }
    //helper method to concat everything but the random guess/seed, as we will be putting the result of this and the
    //seed together to do work
    public static String concat(BlockRecord block){
        //putting items of our block into the string
        String catRecord = 
            block.getTimeStamp() +
            block.getBlockNum() +
            block.getBlockID() +
            block.getSignedID() +
            block.getPreviousHash() + 
            block.getFname() +
            block.getLname() +
            block.getDOB() +
            block.getSSNum() +
            block.getVerificationProcessID() +
            block.getDiag() +
            block.getTreat() +
            block.getRx() +
            block.getTimeStamp();
            
        //returning that string
        return catRecord;            
    }
    //From WorkB.java, a method that creates a string with the set amount of characters(letters and numbers)
    public static String randomAlphaNumeric(int count) {
        //Create a string builder instance
        StringBuilder builder = new StringBuilder();
        //build the string for as long the method call parameter calls for
        while (count-- != 0) {
            //making one single character, we randomly select an index in our
            //global alphanumeric string
          int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
          //we put this single character at the random index to the builder string
          builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        //return the built up string after count is 0
        return builder.toString();
      }
    //the work method, this will test a random guess against a block's combined data values, and when the guess wins, 
    //will become the random seed attribute of the block at hand, and the resulting hash will be the winning hash.
    //Mainly from WorkB.java. The work here is where a certain number (in this case the first four) of the digits of a hash
    //are converted to decimal and then checked to see if the number is under 20000- if it is, then puzzle solved. 
    //returns a verified block
    public static BlockRecord doWork(BlockRecord block){
        //initializing the variables used in the work loop
        String randomSeed = "";
        String dataAndSeed = "";
        String hash = "";
        //the work number is the first four (or however many) hex digits of the resulting 
        //concat in numeric form
        int workNumber = 0;
        //put the previous winning hash of the blockchain into the block, always will be the start since we 
        //are prepending the blocks to the chain as they are verified
        block.setPreviousHash(Blockchain.blockChain.get(0).getWinningHash());
        //set block number
        block.setBlockNum(Blockchain.blockChain.get(0).getBlockNum() + 1);
        //set verification process ID to this process
        block.setVerificationProcessID(Integer.toString(Blockchain.PID));
        //using concat method above to join together all the data in the block
        String blockData = concat(block);
        try {
            while (true) { 
                //using the helper method above to get a random string 8 chars long
                randomSeed = randomAlphaNumeric(8); 
                //putting together the random seed and the block data
                dataAndSeed = blockData + randomSeed;
                //initializing the hash algorithm 
                MessageDigest MD = MessageDigest.getInstance("SHA-256");
                //hashing the dataAndSeed into byte form
                byte[] bytesHash = MD.digest(dataAndSeed.getBytes("UTF-8")); 
                //converting the bytes to hex. Using an outside/XML library.
                hash = DatatypeConverter.printHexBinary(bytesHash); 
                System.out.println("Hash is: " + hash);
                // getting the first four hex digits, converting that to decimal. Here you could make the work 
                //harder by using more of the hex digits, so that the range of possible numbers is far larger 
                //and the chance of solving the below puzzle/condition becomes much smaller 
                workNumber = Integer.parseInt(hash.substring(0,4),16); 
                System.out.println("First 16 bits in Hex and Decimal: " + hash.substring(0,4) +" and " + workNumber);
                //the crux of the work is here, where we determine if the puzzle is solved (the work number is less
                //than 20000, then puzzle is not solved) or greater than 20000, which means the puzzle is solved.
                //here is an oportunity to make it harder, by making the deciding number less, i.e 10000, or even
                //100 to make it a lot of work.
                if (!(workNumber < 20000)){ 
                    System.out.format("%d is not less than 20,000 so we did not solve the puzzle\n\n", workNumber);
                }
                if (workNumber < 20000){
                    System.out.println("block verified!");
                    //add the random seed that solved the puzzle, and the winning hash to the specific block
                    block.setRandomSeed(randomSeed);
                    block.setWinningHash(hash);
                    //also sign this winning hash
                    byte[] signedWinHash = signData(bytesHash, privKey);
                    //convert it to string, place it in block
                    String signedWinHashStr = Base64.getEncoder().encodeToString(signedWinHash);
                    block.setSignedWinningHash(signedWinHashStr);
                    //return the block, now verified
                    break;
                }
                //check through the blockchain, make sure the block hasn't been verified and added yet by 
                //another process
                for (BlockRecord b: blockChain){
                  if (b.getBlockID().equals(block.getBlockID())){
                    //if it has, then this process needs to abandon the block, since it was already put in
                    System.out.println("Abandoning block...");
                    BlockRecord abandonedBlock = new BlockRecord();
                    //marking the block as abandoned so this process knows to leave it
                    abandonedBlock.setBlockID("Abandoned");
                    return abandonedBlock;
                  }
                }
                //sleeping to simulate more work (fake work)
                try{Thread.sleep(7001);}catch(InterruptedException e){}
            }
          }catch(Exception ex) {ex.printStackTrace();}
          //return a verified block
          return block;
    }
      //for process 0, for writing the blockchain to the JSON file. Called in the blockchain worker thread 
      public static void writeToFile(LinkedList<BlockRecord> bc){
        //pretty printing for looking at on the file
        Gson gsonPretty = new GsonBuilder().setPrettyPrinting().create();
        //since this is an array of blocks, start with array bracket per JSON notation
        String JSONWrite = "[";
        for (BlockRecord block: bc){
          JSONWrite += gsonPretty.toJson(block);
          //adding a coma between blocks
          if (bc.indexOf(block) != bc.size() - 1)
            JSONWrite += ",";
      }
        //end bracket
        JSONWrite = JSONWrite + "]";
        //write to the file, called BlockchainLedger
        try (FileWriter writer = new FileWriter("BlockchainLedger.json", false)) {
          writer.write(JSONWrite);
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    
     //converting the arraylist block chain to JSON string, used in the multicast BlockChain  method
     public static String convertBCToJson(LinkedList<BlockRecord> bc){
      //creating a new gson builder instance. 
      Gson gson = new GsonBuilder().create();
      // take the block record object and change it into a JSON object
      String JSON = "[";

      for (BlockRecord block: bc){
         JSON += gson.toJson(block);
        
         //adding a coma between blocks
         if (bc.indexOf(block) != bc.size() - 1)
            JSON += ",";
     }
     JSON = JSON + "]";

     return JSON;
  }
    //simple method for printing a formated block
    public static void printBlock(BlockRecord block){
      String listing = "";
      listing = block.getBlockNum() + ". "
       + block.getTimeStamp() + " "
       + block.getFname() + " "
       + block.getLname() + " "
       + block.getSSNum() + " "
       + block.getDOB() + " "
       + block.getDiag() + " "
       + block.getTreat() + " "
       + block.getRx() + " ";
       System.out.println(listing);
  }
    public static void listCredit(){
        int credit0 = 0;
        int credit1 = 0;
        int credit2 = 0;

        for (BlockRecord b: blockChain){
          if (Integer.parseInt(b.getVerificationProcessID()) == 0)
            credit0 += 1;
          if (Integer.parseInt(b.getVerificationProcessID()) == 1)
            credit1 += 1;
          if (Integer.parseInt(b.getVerificationProcessID()) == 2)
            credit2 += 1;
        }
        System.out.println("Process 0: " + credit0 + " Process 1: " + credit1 + " Process 2: " + credit2);
    }

    public static void main(String args[]) throws Exception {
        int q_len = 6; //standard amount of receiving slots for SysOps
        
        // the PID as gotten from the command line, check if over limit
        if (args.length < 1)
            PID = 0;
        else if (Integer.parseInt(args[0]) > 2){
            System.out.println("Process numbers are 0, 1, or 2");
            throw new IllegalArgumentException();
        }
        else
            PID = Integer.parseInt(args[0]);
        
        System.out.println("Wills Mckenna's Blockchain program. Ctl-c to quit\n");
        System.out.println("Using processID " + PID + "\n");
        
        //setting the port of the particular process so they are different
        new Ports().setPorts(); 
      
        //initialize the public key that will be sent out
        PublicKeyObj pk = initPublicKey(PID);

        // new thread to listen for the start message
        new Thread(new StartServer()).start();
        // new thread to do listen for an incoming public key
        new Thread(new PubKeyServer()).start();
        // new thread to listen for incoming unverified blocks
        new Thread(new UnverifiedBlockServer()).start();
        //new thread to listen for the blockchain
        new Thread(new BlockchainServer()).start();
        System.out.println("Servers set, waiting for start signal...");
        //if this is the second process, multicast the go message
        if (PID == 2){
          new Blockchain().MultiSendStart();
        }
        //sleep so that the start message is multicasted and all servers are started up,
        //all processes start doing the blockchain work at exactly the same time
        try{Thread.sleep(4001);}catch(InterruptedException e){}
        //once the message is received from process 2, start the blockchain creation events
        if (start.equals("go")){
          //multicast the public key
          new Blockchain().MultiSendPK(pk);
          //sleep so that all processes get every PK before moving on
          try{Thread.sleep(4001);}catch(InterruptedException e){}
          //print out the keys on the console of each process
          System.out.println("Public Keys of the processes: ");
          for (PublicKeyObj pk1: pkArray){
            System.out.println(pk1.getProcessID() + ": " + pk1.getPublicKey());
          }
          System.out.println("----------------------------------------------");
          //initialize the blockChain with dummy block 0
          blockChain = initBlockChain();
          // read the file, put the blocks in the UB blockArr
          blockArr = readFile(PID);
          //multicast each block that was read by this process as an unverified block, it will be put in the 
          //priority queue relative to each process
          for (BlockRecord block: blockArr)
              new Blockchain().MultiSendUB(block, Ports.UnverifiedBlockServerBase);
          System.out.println("UBs sent");
          //sleep so we know all the processes got every UB
          try{Thread.sleep(4000);}catch(InterruptedException e){}
          
          //the main driver code for the execution of verifying the blocks in the priority queue, doing work, and then putting them 
          //in the blockchain, depending on how the blockchain is being modified or not 
          //by the other processes
          while (true){
              //sleep a little before working on each UB so the blockchain can settle every once in a while
              try{Thread.sleep(2001);}catch(InterruptedException e){}
              //see how many blocks are in the priority queue
              System.out.println(blockPriorityQueue.size() + " unverified blocks remaining");
              BlockRecord tempBlock = blockPriorityQueue.poll();
              if (tempBlock == null)
                  break;
              BlockRecord verifiedBlock = new BlockRecord();
              //setting up marker that tells us if the block is already in the blockchain or not
              boolean blockExists = false;
              //get the public key for the process that made this block, display PID on console
              String tempPubKey = "";
              for (PublicKeyObj pub: pkArray){
                if (Integer.toString(pub.getProcessID()).equals(tempBlock.getVerificationProcessID())){
                  tempPubKey = pub.getPublicKey();
                  System.out.println("Using the public key from process: " + pub.getProcessID());
                }
              }
              //convert this public key back into bytes, get ready for verification
              byte[] pkinBytes = Base64.getDecoder().decode(tempPubKey);
              //convert the signed blockID into bytes to get ready for verification
              byte[] idSignature = Base64.getDecoder().decode(tempBlock.getSignedID());
              //convert the bytes of the public key into a public key object reference
              X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pkinBytes);
              KeyFactory keyFactory = KeyFactory.getInstance("RSA");
              PublicKey RestoredKey = keyFactory.generatePublic(publicKeySpec);
              //now with the key and both byte arrays, verify
              boolean verified = verifySig(tempBlock.getBlockID().getBytes(), RestoredKey, idSignature);
              //if it verified, do the rest of the work. Otherwise block is not secure, go on to the next block
              if(!verified){
                System.out.println("This block is not signed by the correct owner of the private key, moving on...");
              }
              else {
                //sleep for a little more settling
                try{Thread.sleep(1000);}catch(InterruptedException e){}
                //if passed the verification test, now check if the block is already in the blockchain or not
                for (BlockRecord b: blockChain){
                  if (b.getBlockID().equals(tempBlock.getBlockID())){
                    blockExists = true;
                    System.out.println("Block already in blockchain");
                  }
                }
                //If it does not, attempt to verify it
                while (!blockExists){
                  System.out.println("Attempting to verify block");
                  //do the work/verify the block
                  verifiedBlock = doWork(tempBlock);
                  //checking if blockchain was modified through looking at the winning hash of the head block.
                  //if it is different to a verified block's previous, chain has been modified
                  String previousHash = blockChain.get(0).getWinningHash();
                  //if the block was abandoned, move on to the next block in the PQ
                  if (verifiedBlock.getBlockID().equals("Abandoned"))
                    break;
                  //if the block was able to be verified
                  if (!(verifiedBlock.getBlockID().equals("Abandoned"))){
                    //and if the blockChain was not modified
                    if (verifiedBlock.getPreviousHash().equals(previousHash)){
                      //add it to the blockchain
                      System.out.println("Block verified, adding to blockchain and multicasting...");
                      blockChain.addFirst(verifiedBlock);
                      //multicast the newly modified blockchain to the other processes here
                      new Blockchain().MultiSendBC(blockChain, Ports.BlockchainServerBase);
                      //mark the block as exisiting in the blockchain now
                      blockExists = true;
                    } 
                    //else the blockchain was modified
                    else {
                      //check to see again if it is in the blockchain, if it go on to the next block in PQ
                      for (BlockRecord b: blockChain){
                        if (b.getBlockID().equals(verifiedBlock.getBlockID())){
                          blockExists = true;
                        }
                      }
                      //if at this point blockExists var is still false, the blockchain was modified and the block was not in the chain, 
                      //so attempt to verify it again by going to top of blockexists loop
                      System.out.println("Attempting to work on block again...");
                  }
                }
              //go back here if the same block needs to be worked on again
              }
            }
            //go back here for a new block in the priority queue
          }
            //here is where the program is done processing all UBs, hence blockchain is complete
            System.out.println("BLOCKCHAIN COMPLETE");
        }
        //enter loop to get console command(s) from user
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in)); 
		    try {
			        String input;
			        //do-while loop that waits for user to input  
			        do {
				          System.out.print("(l) to list blockchain, (c) to view credit, (q) to quit:  ");
				          System.out.flush();
				          // puts user input into name var
				          input = in.readLine();
				          // if user pressed l list blocks:
				          if (input.equals("l")){
                    for (BlockRecord b: blockChain)
                      printBlock(b);
                  }
                  //if user pressed c list credits for each process:
                  else if (input.equals("c")) {
                      listCredit();
                  }
                } while (input.indexOf("q") < 0 );
				        // exit message
			          System.out.println("Exited.");
		    } catch (IOException e) {e.printStackTrace();}
    }
}
