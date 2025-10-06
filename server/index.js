const express = require('express')
const SocketIo = require('socket-io')
const io = SocketIo()
const app = express()
const http = require('http')
const server = http.createServer(app)

const PORT = process.env.PORT || 3000

app.use(express.static('public'))





io.attach(server)

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`)
})