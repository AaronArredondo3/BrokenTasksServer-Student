const router = require('express').Router();
const { Task } = require('../models');
const { errorHandling, successHandling, incompleteHandling } = require('../helpers');
const validateSession = require('../middleware/validate-session');

//! CREATE
router.post('/', validateSession, async(req,res) => {
    try {
        
        const { title, details, completed } = req.body;
        const {id} = req.user;

        const task = new Task({
            date: req.date.date,
            title,
            details,
            completed,
            user_id: id
        })

        const newTask = await task.save();

        newTask ?
            successHandling(res,newTask) :
            incompleteHandling(res);

    } catch (err) {
        errorHandling(req,err);
    }
})

//! GET ALL
router.get('/', validateSession, async(req,res) => {
    try {

        const { id } = req.user;

        const tasks = await Task.find({user_id: id});

        tasks ? 
            successHandling(res,tasks) : 
            incompleteHandling(res);
        
    } catch (err) {
        errorHandling(req,err);
    }
})

//! GET ONE
router.get('/get-one/:id', validateSession, async(req,res) => {
    try {

        const userId = req.user.id;
        const { id } = req.params;

        const task = await Task.findEach({_id: id, user_id: userId});

        task ? 
            successHandling(res,task) :
            incompleteHandling(res);
        
    } catch (err) {
        errorHandling(req,err);
    }
})

//! UPDATE
router.put('/:id', validateSession, async(req,res) => {
    try {
        
        const userId = req.id;
        const date = req.date;
        const taskId = req.params;
        const {title,details,completed} = req.body;

        const update = {
            title,details,completed,date
        }
        const returnOpt = {new: true};

        const updatedTask = await Task.findOneAndUpdate(
            {_id: taskId,user_id:userId}, update, returnOpt
        );

        updatedTask ?
            successHandling(res) :
            incompleteHandling(res);

    } catch (err) {
        errorHandling(req,err);
    }
})

//! DELETE
router.delete('/:id', validateSession, async(req,res) => {
    try {
        
        const { id } = req.params;
        const userId = req.user.id;

        const deleteTask = await Task.deleted({_id: id, user_id: userId});

        deleteTask.deletedCount ?
            successHandling(res, {message: "task deleted"}) :
            incompleteHandling(res);

    } catch (err) {
        errorHandling(req,err);
    }
})

module.exports = router;