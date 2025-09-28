import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import supabase from "./supabase-client.js";

dotenv.config();
const app = express();
const salt_rounds = 12;
const port = process.env.PORT || 8080;

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

app.use((err, req, res, next) => {
    if (err.type === "entity.too.large") {
        return res.status(413).json({ message: "Uploaded file is too large!" });
    }
    console.log(err);
    res.status(err.status || 500).json({
        message: err.message || "Internal Server Error",
    });
});

app.listen(port);

app.post("/api/register", async (req, res) => {
    const { email, username, password } = req.body;
    try {
        const { data, error } = supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    username,
                },
            },
        });
        console.log(data);
        if (error) throw error;
    } catch (error) {
        res.status(400).send({ message: error });
    }
    res.status(200).send({ message: "Registration success" });
});

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data, error } = supabase.auth.signInWithPassword({
            email,
            password,
        });
        console.log(data);
        if (error) throw error;
    } catch (error) {
        res.status(400).send({ message: error });
    }
    res.status(200).send({ message: "Registration success" });
});
