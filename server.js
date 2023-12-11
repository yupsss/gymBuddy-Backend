require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const workoutRoutes = require('./routes/workout')
const userRoutes = require('./routes/user')



// express app
const app = express();

// app.set('view engine', 'ejs');
app.use(cors());

// middleware       -- anything that run bw the request by browser and the request obj in backend eg here it is get request 

app.use(express.json());

app.use((req,res,next)=>{
    console.log(req.path,req.method);
    next();
})


// routes 
app.use('/api/workouts',workoutRoutes);
app.use('/api/user',userRoutes);


//connect to db
mongoose.connect(process.env.MONGO_URI).then(()=>{
    
    app.listen(process.env.PORT, ()=>{console.log(`------------connnected to db and listning in PORT ${process.env.PORT} ------------1`)});

}).catch(err => console.log(err))

// listen for requests
// app.listen(4000, ()=>{console.log('------------listning in port 4000-------------')});
// app.listen(process.env.PORT, ()=>{console.log(`------------listning in PORT ${process.env.PORT} ------------1`)});


