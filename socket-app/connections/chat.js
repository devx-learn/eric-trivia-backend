let connection = {
    onConnect: onConnect,
}

let messageId = 0;
let userId = 0;
let users = {};


function onConnect(socket) {
    let interval = 1000;
    let messageCount = 10;
    let timer = null;

    socket.on('signin', (username) => {
        users[socket.id] = {
            username: username,
            userId: userId++
        };
        let userList = {};
        Object.keys(users).forEach(id =>{
            userList[users[id].userId] = {
                username:users[id].username,
                userId: users[id].userId
            }
        })
        this.emit('userlist', userList);
    })

    socket.on('disconnect', () => {
        delete users[socket.id];
        this.emit('userlist', Object.keys(users).map(id =>{
            return users[id]
        }));
    })

    socket.on('send', (message) => {
        message.id = messageId++;
        message.userId = users[socket.id].userId;
        message.timeStamp = new Date().getTime();
        this.emit('new-message', message);
    })

    socket.on('typing', (data) => {
        socket.broadcast.emit('typing', users[socket.id]);
    })
}

module.exports = connection;
