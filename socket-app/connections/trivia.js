let connection = {
    onConnect: onConnect,
}

let messageId = 0;
let userId = 0;
let users = {};

const questions = [
  {question:"Who is the current president of the United States",
   answer:"Donald Trump",
   points: 10
  },
  {
   question:"What is the absolute value of pi?",
   answer:"3.1412312312347689076536784901736451718903476",
   points: 10
  },
  {
   question:"What is my name?",
   answer:"Eric Gelencser",
   points: 10
  },
  {
  question:"How old is Morgan Freeman?",
  answer:"57",
  points: 10
  },
  {
  question:"How old am I?",
  answer:"28",
  points: 10
  },
]

function onConnect(socket) {
    let interval = 1000;
    let messageCount = 10;
    let timer = null;

//users sign in and it sends a questions
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
        this.emit('question', questions[0]);
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
