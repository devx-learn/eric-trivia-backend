
let fs = require('fs');
let path = require('path');
let io = require('socket.io');

class socketApp {
    constructor(server) {
        this.io = io(server);
        let connectionDir = './connections';
        let files = fs.readdirSync(path.join(__dirname, connectionDir));
        if (files) {
            files.forEach((file) => {
                try {
                    let connection = require(path.join(__dirname, connectionDir, file));
                    let connectionName = path.basename(file,'.js');
                    let socketServer = this.io.of('/' + connectionName);
                    socketServer.on('connection', connection.onConnect.bind(socketServer));
                    console.log("Loaded socket connection '" + connectionName + "'")
                }
                catch (ex) {
                    console.log("Unable to load socket connection " + file + '\n' + ex.stack);
                }
            })
        }
    }
}

module.exports = socketApp;