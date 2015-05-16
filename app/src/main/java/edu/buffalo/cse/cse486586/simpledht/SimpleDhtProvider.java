package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {

    static final String TAG = SimpleDhtProvider.class.getSimpleName();
    static final int SERVER_PORT = 10000;
    static Node nodeList = null;
    static MatrixCursor cursor = null;
    static boolean isQueryAllComplete = false;
    static boolean isDeleteAllComplete = false;
    static Map<String, String> avdPort = new HashMap<>();

    private String getPort(){
        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        return String.valueOf((Integer.parseInt(portStr) * 2));
    }

    private void queryContext(){
        for(String file: getContext().fileList()){
            try {
                FileInputStream in = getContext().openFileInput(file);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String value = reader.readLine();
                cursor.addRow(new Object[]{file, value.trim()});
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File not found");
            } catch (IOException e) {
                Log.e(TAG, "IOException");
            }
        }
    }

    private void queryAll(ObjectOutputStream out){
        for(String file: getContext().fileList()){
            try {
                FileInputStream in = getContext().openFileInput(file);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String value = reader.readLine();
                out.writeObject(new Object[]{file, value.trim()});
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File not found");
            } catch (IOException e) {
                Log.e(TAG, "IOException");
            }
        }
    }

    private String genHash(String input){
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] sha1Hash = sha1.digest(input.getBytes());
            Formatter formatter = new Formatter();
            for (byte b : sha1Hash) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        }catch (NoSuchAlgorithmException e){
            Log.e(TAG, "Gen Hash Error");
            return null;
        }
    }

    private class Node {
        String portNum;
        String portNumHash;
        Node next;
        Node prev;

        public Node(String portNumHash, String portNum, Node next, Node prev) {
            this.portNumHash = portNumHash;
            this.portNum = portNum;
            this.next = next;
            this.prev = prev;
        }
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        if(selection.equals("\"@\"")){
            for(String file: getContext().fileList()){
                getContext().deleteFile(file);
            }
        }else if (selection.equals("\"*\"")) {
            for(String file: getContext().fileList()){
                getContext().deleteFile(file);
            }
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", nodeList.portNum, nodeList.next.portNum);
            while (!isDeleteAllComplete);
        }else {
            getContext().deleteFile(selection);
        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        String key = "";
        String value = "";
        for(String column: values.keySet()) {
            if(column.equals("key")){
                key = (String) values.get(column);
            } else if(column.equals("value")){
                value = (String) values.get(column);
            }
        }

        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, getPort());
        return null;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub

        avdPort.put("11108", "5554");
        avdPort.put("11112", "5556");
        avdPort.put("11116", "5558");
        avdPort.put("11120", "5560");
        avdPort.put("11124", "5562");

        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "Can't create a ServerSocket");
            return false;
        }

        String port = getPort();
        nodeList = new Node(genHash(avdPort.get(port)), port, null, null);

        if(!port.equals("11108")){
            Log.d(TAG, port);
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "join", port, "11108");
        }
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        // TODO Auto-generated method stub
        Log.v("query", selection);
        cursor = new MatrixCursor(new String[]{"key", "value"});

        if(selection.equals("\"@\"")){
            queryContext();
        }else if (selection.equals("\"*\"")){
            queryContext();

            if(nodeList.next != null) {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "*", nodeList.portNum, nodeList.next.portNum);
                while (!isQueryAllComplete) ;
            }
        } else{
            try {
                FileInputStream in = getContext().openFileInput(selection);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String value = reader.readLine();
                cursor.addRow(new Object[]{selection, value.trim()});
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File not found");

                //File is not in this node. Search the remaining nodes
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, nodeList.next.portNum, nodeList.portNum);
                try {
                    Thread.sleep(2000);
                }catch (InterruptedException ex){
                    Log.e(TAG, "Thread Sleep Interrupted");
                }
            } catch (IOException e) {
                Log.e(TAG, "IOException");
            }
        }
        return cursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            //Used for insert
            Set<String> customize = new HashSet<>();
            //Used for node join
            Set<String> joinSet = new HashSet<>();

            while(true) {
                try {
                    Socket socket = serverSocket.accept();
                    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                    String input = "";
                    try {
                        input = (String) in.readObject();
                    }catch (ClassNotFoundException e){
                        Log.e(TAG, "ServerTask Class Not Found Exception");
                    }
                    Log.e(TAG, input);

                    if (input == null) {
                        continue;
                    }
                    if(input.equals("join")){
                        String dest = null;
                        try {
                            dest = (String) in.readObject();
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }

                        String hash = genHash(avdPort.get(dest));
                        Log.d(TAG, hash + " " + nodeList.portNumHash);

                        if(joinSet.contains(dest)){
                            //Node has completed one round
                            if ((nodeList.portNumHash.compareTo(nodeList.next.portNumHash) < 0)&&
                                (nodeList.portNumHash.compareTo(nodeList.prev.portNumHash) < 0)){
                                //This is the smallest of all the nodes and so should handle the join request
                                Node temp = nodeList.prev;

                                nodeList.prev = new Node(hash, dest, nodeList.prev, nodeList);
                                Log.d(TAG, "update:" + nodeList.prev.portNum + ":" + nodeList.next.portNum);
                                updateJoin("update:" + temp.portNum + ":" + nodeList.portNum, dest);
                                updateJoin("update:" + "null" + ":" + dest, temp.portNum);
                            }else {
                                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "join", dest, nodeList.next.portNum);
                            }
                            continue;
                        }else {
                            joinSet.add(dest);
                        }

                        if(nodeList.next == null && nodeList.prev == null){
                            nodeList.prev = new Node(hash, dest, nodeList, nodeList);
                            nodeList.next = new Node(hash, dest, nodeList, nodeList);

                            Log.d(TAG, "update:" + nodeList.prev.portNum + ":" + nodeList.next.portNum);
                            updateJoin("update:"+nodeList.portNum+":"+nodeList.portNum, dest);
                        }else {
                            if ((hash.compareTo(nodeList.portNumHash) > 0) &&
                                (hash.compareTo(nodeList.next.portNumHash) <= 0)){
                                    Node temp = nodeList.next;
                                    nodeList.next = new Node(hash, dest, nodeList, nodeList.next);
                                    Log.d(TAG, "update:" + nodeList.prev.portNum + ":" + nodeList.next.portNum);

                                    updateJoin("update:" + nodeList.portNum + ":" + temp.portNum, dest);
                                    updateJoin("update:" + dest + ":" + "null", temp.portNum);
                            }else {
                                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "join", dest, nodeList.next.portNum);
                            }
                        }
                    }else if(input.startsWith("update")) {
                        String[] msg = input.split(":");

                        //If 'null' then it means no need to update that field.
                        //Only update field that has changed because of node join
                        if(!msg[1].equals("null"))
                            nodeList.prev = new Node(genHash(avdPort.get(msg[1])), msg[1], null, nodeList);
                        if(!msg[2].equals("null"))
                            nodeList.next = new Node(genHash(avdPort.get(msg[2])), msg[2], nodeList, null);
                    }else if(input.equals("query")) {
                        Log.d(TAG, "In query");
                        String buffer = null;

                        try {
                            buffer = (String)in.readObject();
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                        String[] msg = buffer.split(":");

                        try {
                            FileInputStream stream = getContext().openFileInput(msg[0]);
                            BufferedReader reader = new BufferedReader(new InputStreamReader(stream));

                            String value = reader.readLine();
                            reader.close();

                            try {
                                Socket temp = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(msg[1]));

                                ObjectOutputStream out = new ObjectOutputStream(temp.getOutputStream());
                                out.writeObject("result");
                                out.writeObject(new Object[]{msg[0], value.trim()});
                                Log.d(TAG, msg[0] + value);
                                out.close();

                                temp.close();
                            } catch (UnknownHostException e) {
                                Log.e(TAG, "Client Task Unknown Host exception");
                            } catch (IOException e) {
                                Log.e(TAG, "Client Task socket IOException");
                            }
                        } catch (FileNotFoundException e) {
                            Log.e(TAG, "File not found");

                            //File is not in this node. Search the remaining nodes
                            writeToServer("query", buffer, nodeList.next.portNum);
                        } catch (IOException e) {
                            Log.e(TAG, "IOException");
                        }
                    }else if(input.equals("result")) {
                        try {
                            Object[] result = (Object[]) in.readObject();
                            Log.d(TAG, result.toString());
                            cursor.addRow(result);
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                    }else if(input.equals("*")) {
                        try {
                            String sourcePort = (String)in.readObject();

                            if(!nodeList.portNum.equals(sourcePort)){
                                Socket returnToSource = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(sourcePort));
                                ObjectOutputStream out = new ObjectOutputStream(returnToSource.getOutputStream());
                                out.writeObject("*result");
                                //Send the results to the requested node once found.
                                queryAll(out);
                                out.close();
                                returnToSource.close();

                                //Retrieve results from other nodes
                                writeToServer("*", sourcePort, nodeList.next.portNum);
                            }else{
                                isQueryAllComplete = true;
                            }

                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                    }else if(input.equals("*result")){
                        try{
                            Object[] result = null;
                            while ((result = (Object[])in.readObject()) != null){
                                cursor.addRow(result);
                            }
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                    }else if(input.equals("delete")) {
                        try{
                            String dest = (String)in.readObject();

                            if(!nodeList.portNum.equals(dest)){
                                for(String file: getContext().fileList()){
                                    getContext().deleteFile(file);
                                }

                                //delete all the files in all the remaining nodes
                                writeToServer("delete", dest, nodeList.next.portNum);
                            }else {
                                isDeleteAllComplete = true;
                            }
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                    }else{
                        String[] msg = null;
                        try {
                            msg = ((String)in.readObject()).split(":");
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }

                        String hashKey = genHash(msg[0]);

                        //If no other node exists
                        if(nodeList.prev == null && nodeList.next == null){
                            persistInformation(msg);
                        }else if((hashKey.compareTo(nodeList.prev.portNumHash) > 0)
                                && (hashKey.compareTo(nodeList.portNumHash) <= 0)) {
                            //Key belongs to this node
                            persistInformation(msg);
                        }else {
                            if(customize.contains(msg[0]) &&
                                    (nodeList.portNumHash.compareTo(nodeList.next.portNumHash) < 0) &&
                                    (nodeList.portNumHash.compareTo(nodeList.prev.portNumHash) < 0)){
                                //Key has completed one round and this node is the smallest
                                persistInformation(msg);
                            }else {
                                writeToServer("default", msg[0] + ":" + msg[1], nodeList.next.portNum);
                                customize.add(msg[0]);
                            }
                        }
                    }

                    socket.close();
                } catch (UnknownHostException e) {
                    Log.e(TAG, "ServerTask UnknownHostException");
                } catch (IOException e) {
                    Log.e(TAG, "ServerTask IOException");
                }
            }

        }

        private void writeToServer(String firstMsg, String secondMsg, String port){
            try {
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(port));

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(firstMsg);
                out.writeObject(secondMsg);
                socket.close();
            } catch (UnknownHostException e) {
                Log.e(TAG, "Client Task Unknown Host exception");
            } catch (IOException e) {
                Log.e(TAG, "Client Task socket IOException");
            }
        }

        private void updateJoin(String msg, String dest){
            try {
                Socket temp = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(dest));

                ObjectOutputStream out = new ObjectOutputStream(temp.getOutputStream());
                out.writeObject(msg);
                out.close();

                temp.close();
            }catch (UnknownHostException e){
                Log.e(TAG, "Client Task Unknown Host exception");
            }catch(IOException e){
                Log.e(TAG, "Client Task socket IOException");
            }
        }

        private void persistInformation(String[] msg){
            Log.e(TAG, "Persisting information:" + msg[0]);
            try {
                FileOutputStream file = getContext().openFileOutput(msg[0], Context.MODE_PRIVATE);

                file.write(msg[1].getBytes());
                file.close();
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File Not found");
            } catch (IOException e) {
                Log.e(TAG, "Unable to write to file");
            }
        }
    }

    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {
            if(msgs[0].equals("join")) {
                Log.d(TAG, "join" + ":" + msgs[1] + ":" + msgs[2]);
                writeToServer("join", msgs[1], msgs[2]);
            } else if(msgs[0].equals("query")){
                //writeToServer("query:" + msgs[1] + ":" + msgs[3], msgs[2]);
                writeToServer("query", msgs[1] + ":" + msgs[3], msgs[2]);
            } else if(msgs[0].equals("*")){
                writeToServer("*", msgs[1], msgs[2]);
            } else if(msgs[0].equals("delete")){
                writeToServer("delete", msgs[1], msgs[2]);
            }else {
                String key = msgs[0];
                String value = msgs[1];

                writeToServer("default", key + ":" + value, msgs[2]);
            }
            return null;
        }

        private void writeToServer(String firstMsg, String secondMsg, String port){
            try{
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(port));

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(firstMsg);
                out.writeObject(secondMsg);
                socket.close();
            } catch (UnknownHostException e) {
                Log.e(TAG, "Client Task Unknown Host exception");
            } catch (IOException e) {
                Log.e(TAG, "Client Task socket IOException");
            }
        }
    }
}
