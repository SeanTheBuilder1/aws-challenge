import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import supabase from "./supabase-client.js";
import cors from "cors";
import { body, validationResult } from "express-validator";

dotenv.config();
const app = express();
const salt_rounds = 12;
const port = process.env.PORT || 8080;

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

const whitelist = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "https://aws-challenge-frontend.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow requests with no origin (like curl, server-to-server)
      if (!origin) return callback(null, true);

      if (whitelist.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        // reject - will result in no CORS headers being sent
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  }),
);

app.use((err, req, res, next) => {
  if (err.type === "entity.too.large") {
    return res.status(413).json({ message: "Uploaded file is too large!" });
  }
  console.log(err);
  res.status(err.status || 500).json({
    message: err.message || "Internal Server Error",
  });
});

const validateFunction = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send({ message: errors.array()[0].msg });
  } else {
    return next();
  }
};

const validateUser = async (req, res, next) => {
  const token = req.cookies.access_token;
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    res
      .status(401)
      .send({ message: "Failed to verify refresh token, call refresh" });
    return;
  }

  const { user_id, username } = payload;

  const { count: user_check_count, error: user_check_error } = await supabase
    .from("users")
    .select("user_id", { count: "exact", head: true })
    .eq("user_id", user_id);

  if (user_check_error) {
    console.log(user_check_error);
    return res.status(400).send({ message: "Database error" });
  }

  if (user_check_count === 0) {
    return res
      .status(404)
      .send({ message: "User corresponding to token unknown" });
  }
  res.locals.validate_user_payload = payload;
  return next();
};

const validateCreator = async (req, res, next) => {
  const { team_id } = req.body;
  const { user_id, username } = res.locals.validate_user_payload;
  const { count: is_creator_count, error: is_creator_error } = await supabase
    .from("teams")
    .select("creator, team_id", { count: "exact", head: true })
    .eq("creator", user_id)
    .eq("team_id", team_id);

  if (is_creator_error) {
    console.log(is_creator_error);
    return res.status(400).send({ message: "Database error" });
  }
  if (is_creator_count === 1) {
    return next();
  }
  return res.status(403).send({ message: "Not team creator" });
};

const validateCreatorAndMembership = async (req, res, next) => {
  const { team_id } = req.body;
  const { user_id, username } = res.locals.validate_user_payload;

  const { count: is_member_count, error: is_member_error } = await supabase
    .from("team_membership")
    .select("team_id, user_id", { count: "exact", head: true })
    .eq("team_id", team_id)
    .eq("user_id", user_id);

  if (is_member_error) {
    console.log(is_member_error);
    return res.status(400).send({ message: "Database error" });
  }
  if (is_member_count === 1) {
    return next();
  }
  const { count: is_creator_count, error: is_creator_error } = await supabase
    .from("teams")
    .select("creator, team_id", { count: "exact", head: true })
    .eq("creator", user_id)
    .eq("team_id", team_id);

  if (is_creator_error) {
    console.log(is_creator_error);
    return res.status(400).send({ message: "Database error" });
  }
  if (is_creator_count === 1) {
    return next();
  }
  return res.status(403).send({ message: "Not team member or creator" });
};

const validateMembership = async (req, res, next) => {
  const { team_id } = req.body;
  const { user_id, username } = res.locals.validate_user_payload;

  const { count: is_member_count, error: is_member_error } = await supabase
    .from("team_membership")
    .select("team_id, user_id", { count: "exact", head: true })
    .eq("team_id", team_id)
    .eq("user_id", user_id);

  if (is_member_error) {
    console.log(is_member_error);
    return res.status(400).send({ message: "Database error" });
  }
  if (is_member_count === 1) {
    return next();
  }
  return res.status(403).send({ message: "Not team member" });
};

app.listen(port);

app.post(
  "/api/register",
  body("email")
    .exists()
    .withMessage("Email required")
    .isEmail()
    .withMessage("Invalid email"),
  body("username")
    .notEmpty()
    .withMessage("Username required")
    .isString()
    .withMessage("Invalid username"),
  body("password")
    .notEmpty()
    .withMessage("Password required")
    .isString()
    .withMessage("Invalid password"),
  validateFunction,
  async (req, res) => {
    const { email, username, password } = req.body;
    const { count: dupe_count, error: dupe_error } = await supabase
      .from("users")
      .select("username, email", { count: "exact", head: true })
      .or(`username.eq.${username},email.eq.${email}`);

    if (dupe_error) {
      console.log(dupe_error);
      return res.status(400).send({ message: "Database error" });
    }
    if (dupe_count !== 0) {
      return res
        .status(409)
        .send({ message: "Username or email is already registered" });
    }
    const hash = await bcrypt.hash(password, salt_rounds);
    try {
      const { error } = await supabase
        .from("users")
        .insert({ email: email, username: username, password_hash: hash });
      if (error) {
        throw error;
      }
    } catch (error) {
      console.log(error);
    }
    res.status(200).send({ message: "Registration success" });
  },
);

app.post(
  "/api/login",
  body("email")
    .exists()
    .withMessage("Email required")
    .isEmail()
    .withMessage("Invalid email"),
  body("password")
    .notEmpty()
    .withMessage("Password required")
    .isString()
    .withMessage("Invalid password"),
  validateFunction,
  async (req, res) => {
    const { email, password } = req.body;
    const { data, error } = await supabase
      .from("users")
      .select("username, user_id, email, password_hash")
      .eq("email", email);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    if (data.length == 0) {
      return res.status(400).send({ message: "User does not exist" });
    }
    const result = data[0];
    const passed = await bcrypt.compare(password, result.password_hash);
    if (!passed) {
      return res.status(401).send({ message: "Wrong password!" });
    }
    const token = jwt.sign(
      {
        user_id: result.user_id,
        username: result.username,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      },
    );
    const refresh_uuid = crypto.randomUUID();
    const refresh_token = jwt.sign(
      {
        user_id: result.user_id,
        username: result.username,
        token_uuid: refresh_uuid,
      },
      process.env.REFRESH_JWT_SECRET,
      {
        expiresIn: "30d",
      },
    );
    const token_hash = await bcrypt.hash(refresh_token, salt_rounds);
    const expiry_date = new Date();
    expiry_date.setDate(expiry_date.getDate() + 30);
    const { error: insert_error } = await supabase
      .from("refresh_tokens")
      .insert({
        user_id: result.user_id,
        token_hash: token_hash,
        expires_at: expiry_date.toISOString(),
        refresh_uuid: refresh_uuid,
      });
    if (insert_error) {
      console.log(insert_error);
      return res.status(400).send({ message: "Database error" });
    }
    res.cookie("refresh_token", refresh_token, {
      httpOnly: true,
      path: "/api/refresh",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.cookie("refresh_token", refresh_token, {
      httpOnly: true,
      path: "/api/logout",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });

    res.status(200).send({ message: "Login success" });
  },
);

app.get("/api/refresh", async (req, res) => {
  res.set({
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    Expires: "0",
  });
  const refresh_token = req.cookies.refresh_token;
  if (!refresh_token)
    return res.status(401).send({ message: "No refresh token" });
  let payload;
  try {
    payload = jwt.verify(refresh_token, process.env.REFRESH_JWT_SECRET);
  } catch (error) {
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/refresh",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/logout",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("access_token", {
      httpOnly: true,
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.status(401).send({ message: "Invalid refresh token" });
    return;
  }

  const { user_id, username, token_uuid } = payload;

  const { data, error } = await supabase
    .from("refresh_tokens")
    .select("user_id, token_hash, expires_at")
    .eq("refresh_uuid", token_uuid);

  if (error) {
    console.log(error);
    return res.status(400).send({ message: "Database error" });
  }

  if (data.length !== 1) {
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/refresh",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/logout",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("access_token", {
      httpOnly: true,
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.status(401).send({ message: "Refresh token not found in database" });
    return;
  }
  const result = data[0];
  const passed = bcrypt.compare(refresh_token, result.token_hash);

  if (!passed) {
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/refresh",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/logout",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("access_token", {
      httpOnly: true,
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.status(401).send({ message: "Refresh token hash mismatch" });
    return;
  }
  if (new Date(result.expires_at) < new Date()) {
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/refresh",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/logout",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("access_token", {
      httpOnly: true,
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.status(401).send({ message: "Refresh token expired" });
    return;
  }

  const new_token = jwt.sign(
    {
      user_id: result.user_id,
      username: username,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "1h",
    },
  );
  res.cookie("access_token", new_token, {
    httpOnly: true,
    sameSite: "None",
    partitioned: true,
    secure: true,
  });
  res.status(200).send({ message: "Refresh successful" });
});

app.post(
  "/api/create-team",
  body("team_name").notEmpty().withMessage("Team name required"),
  body("description")
    .optional()
    .isString()
    .withMessage("Description must be a string"),
  validateFunction,
  validateUser,
  async (req, res) => {
    const { team_name, description } = req.body;

    const { user_id, username } = res.locals.validate_user_payload;

    const { count: user_check_count, error: user_check_error } = await supabase
      .from("users")
      .select("user_id", { count: "exact", head: true })
      .eq("user_id", user_id);

    if (user_check_error) {
      console.log(user_check_error);
      return res.status(400).send({ message: "Database error" });
    }

    if (user_check_count === 0) {
      return res
        .status(404)
        .send({ message: "User corresponding to token unknown" });
    }
    const { data, error } = await supabase.from("teams").insert({
      name: team_name,
      creator: user_id,
      description: description ? description : "",
    });
    return res.status(200).send({ message: "Team created successfully" });
  },
);

app.post(
  "/api/join-team",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  validateFunction,
  validateUser,
  async (req, res) => {
    const { team_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { count: is_creator_count, error: is_creator_error } = await supabase
      .from("teams")
      .select("creator, team_id", { count: "exact", head: true })
      .eq("creator", user_id)
      .eq("team_id", team_id);

    if (is_creator_error) {
      console.log(is_creator_error);
      return res.status(400).send({ message: "Database error" });
    }

    if (is_creator_count !== 0) {
      return res
        .status(403)
        .send({ message: "Team creators are already considered joined" });
    }
    const { count: dupe_join_count, error: dupe_join_error } = await supabase
      .from("team_membership")
      .select("team_id, user_id", { count: "exact", head: true })
      .eq("team_id", team_id)
      .eq("user_id", user_id);

    if (dupe_join_error) {
      console.log(dupe_join_error);
      return res.status(400).send({ message: "Database error" });
    }
    if (dupe_join_count !== 0) {
      return res.status(403).send({ message: "Already joined team" });
    }
    const { error } = await supabase
      .from("team_membership")
      .insert({ team_id: team_id, user_id: user_id });
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ message: "Team joined successfully" });
  },
);

app.post(
  "/api/post-team",

  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("post_subject")
    .notEmpty()
    .withMessage("Subject is required")
    .isString()
    .withMessage("Subject must be a string"),
  body("post_body").optional().isString().withMessage("Body must be a string"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, post_subject, post_body } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { error } = await supabase.from("team_posts").insert({
      team_id: team_id,
      user_id: user_id,
      post_subject: post_subject,
      post_body: post_body ? post_body : "",
    });
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ message: "Posted successfully" });
  },
);

app.get("/api/list-teams", validateFunction, validateUser, async (req, res) => {
  const { user_id, username } = res.locals.validate_user_payload;
  const { data, error } = await supabase
    .from("teams")
    .select(
      "team_id, created_at, name, creator, description, creator_name:users!creator(username)",
    );
  if (error) {
    console.log(error);
    return res.status(400).send({ message: "Database error" });
  }
  return res.status(200).send({ teams: data });
});

app.post(
  "/api/list-team-members",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  validateFunction,
  validateUser,
  async (req, res) => {
    const { team_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;
    const { data, error } = await supabase
      .from("team_membership")
      .select("team_id, joined_at, user_id, users!user_id(username)")
      .eq("team_id", team_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ members: data });
  },
);

app.post(
  "/api/team-details",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { user_id, username } = res.locals.validate_user_payload;
    res.status(200).send({ message: "Is member" });
  },
);

app.post(
  "/api/post-team-task",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("task_subject")
    .notEmpty()
    .withMessage("Subject is required")
    .isString()
    .withMessage("Subject must be a string"),
  body("task_body").optional().isString().withMessage("Body must be a string"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, task_subject, task_body } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { error } = await supabase.from("team_tasks").insert({
      team_id: team_id,
      user_id: user_id,
      task_subject: task_subject,
      task_body: task_body ? task_body : "",
    });
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ message: "Posted successfully" });
  },
);

app.post(
  "/api/complete-team-task",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("task_id")
    .exists()
    .withMessage("Task ID is required")
    .isInt()
    .withMessage("Task ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, task_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { error } = await supabase
      .from("team_tasks")
      .update({ completed: true })
      .eq("team_id", team_id)
      .eq("task_id", task_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ message: "Task completed" });
  },
);

app.post(
  "/api/comment-team-task",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("task_id")
    .exists()
    .withMessage("Task ID is required")
    .isInt()
    .withMessage("Task ID must be an integer ID"),
  body("comment")
    .notEmpty()
    .withMessage("Comment is required")
    .isString()
    .withMessage("Comment must be a string"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, task_id, comment } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { error } = await supabase
      .from("team_task_comments")
      .insert({ task_id: task_id, user_id: user_id, comment: comment });
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ message: "Comment posted" });
  },
);

app.post(
  "/api/get-team-posts",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;
    const { data, error } = await supabase
      .from("team_posts")
      .select(
        "post_id, created_at, user_id, post_subject, post_body, users!user_id(username)",
      )
      .eq("team_id", team_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ posts: data });
  },
);

app.post(
  "/api/get-team-tasks",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { data, error } = await supabase
      .from("team_tasks")
      .select(
        "task_id, created_at, user_id, task_subject, task_body, completed, users!user_id(username)",
      )
      .eq("team_id", team_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ tasks: data });
  },
);

app.post(
  "/api/get-post",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("post_id")
    .exists()
    .withMessage("Post ID is required")
    .isInt()
    .withMessage("Post ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, post_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { data, error } = await supabase
      .from("team_posts")
      .select(
        "post_id, created_at, user_id, post_subject, post_body, users!user_id(username)",
      )
      .eq("post_id", post_id)
      .single();
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ post: data });
  },
);

app.post(
  "/api/get-task",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("task_id")
    .exists()
    .withMessage("Task ID is required")
    .isInt()
    .withMessage("Task ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, task_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { data, error } = await supabase
      .from("team_tasks")
      .select(
        "task_id, created_at, user_id, task_subject, task_body, completed, users!user_id(username)",
      )
      .eq("task_id", task_id)
      .single();
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ task: data });
  },
);

app.post(
  "/api/get-task-comments",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("task_id")
    .exists()
    .withMessage("Task ID is required")
    .isInt()
    .withMessage("Task ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, task_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { data, error } = await supabase
      .from("team_task_comments")
      .select(
        "comment_id, task_id, created_at, user_id, comment, users!user_id(username)",
      )
      .eq("task_id", task_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ comments: data });
  },
);

app.get(
  "/api/get-user-info",
  validateFunction,
  validateUser,
  async (req, res) => {
    res.set({
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      Expires: "0",
    });
    const { user_id, username } = res.locals.validate_user_payload;
    return res.status(200).send({
      message: "Info got",
      user_info: { user_id: user_id, username: username },
    });
  },
);

app.post("/api/logout", async (req, res) => {
  const token = req.cookies.access_token;

  const refresh_token = req.cookies.refresh_token;
  if (!refresh_token)
    return res.status(403).send({ message: "No refresh token to logout" });
  let payload;
  try {
    payload = jwt.verify(refresh_token, process.env.REFRESH_JWT_SECRET);
  } catch (error) {
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/refresh",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("refresh_token", {
      httpOnly: true,
      path: "/api/logout",
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.clearCookie("access_token", {
      httpOnly: true,
      sameSite: "None",
      partitioned: true,
      secure: true,
    });
    res.status(401).send({ message: "failed" });
    return;
  }

  const { user_id, username, token_uuid } = payload;
  const { error } = await supabase
    .from("refresh_tokens")
    .delete()
    .eq("refresh_uuid", token_uuid);

  if (error) {
    console.log(error);
    return res.status(400).send({ message: "Database error" });
  }
  res.clearCookie("access_token", {
    httpOnly: true,
    sameSite: "None",
    partitioned: true,
    secure: true,
  });
  res.clearCookie("refresh_token", {
    httpOnly: true,
    path: "/api/refresh",
    sameSite: "None",
    partitioned: true,
    secure: true,
  });
  res.clearCookie("refresh_token", {
    httpOnly: true,
    path: "/api/logout",
    sameSite: "None",
    partitioned: true,
    secure: true,
  });
  res.status(200).send({ message: "Logout successful" });
});

app.post(
  "/api/delete-task",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("task_id")
    .exists()
    .withMessage("Task ID is required")
    .isInt()
    .withMessage("Task ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, task_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { count, error } = await supabase
      .from("team_tasks")
      .select("*", { count: "exact", head: true })
      .eq("task_id", task_id)
      .eq("user_id", user_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    if (count !== 1) {
      return res.status(403).send({ message: "Not creator of task" });
    }
    const { data, error: delete_error } = await supabase
      .from("team_tasks")
      .delete()
      .eq("task_id", task_id);
    if (delete_error) {
      console.log(delete_error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ message: "Task deleted successfully" });
  },
);

app.post(
  "/api/delete-post",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("post_id")
    .exists()
    .withMessage("Post ID is required")
    .isInt()
    .withMessage("Post ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,
  async (req, res) => {
    const { team_id, post_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { count, error } = await supabase
      .from("team_posts")
      .select("*", { count: "exact", head: true })
      .eq("post_id", post_id)
      .eq("user_id", user_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    if (count !== 1) {
      return res.status(403).send({ message: "Not creator of post" });
    }
    const { data, error: delete_error } = await supabase
      .from("team_posts")
      .delete()
      .eq("post_id", post_id);
    if (delete_error) {
      console.log(delete_error);
      return res.status(400).send({ message: "Database error" });
    }
    return res.status(200).send({ message: "Post deleted successfully" });
  },
);

app.post(
  "/api/is-post-creator",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("post_id")
    .exists()
    .withMessage("Post ID is required")
    .isInt()
    .withMessage("Post ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,

  async (req, res) => {
    const { team_id, post_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { count, error } = await supabase
      .from("team_posts")
      .select("*", { count: "exact", head: true })
      .eq("post_id", post_id)
      .eq("user_id", user_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    if (count !== 1) {
      return res
        .status(200)
        .send({ message: "Not creator of post", creator: false });
    }
    return res.status(200).send({ message: "Creator of post", creator: true });
  },
);

app.post(
  "/api/is-task-creator",
  body("team_id")
    .exists()
    .withMessage("Team ID is required")
    .isInt()
    .withMessage("Team ID must be an integer ID"),
  body("task_id")
    .exists()
    .withMessage("Task ID is required")
    .isInt()
    .withMessage("Task ID must be an integer ID"),
  validateFunction,
  validateUser,
  validateCreatorAndMembership,

  async (req, res) => {
    const { team_id, task_id } = req.body;
    const { user_id, username } = res.locals.validate_user_payload;

    const { count, error } = await supabase
      .from("team_tasks")
      .select("*", { count: "exact", head: true })
      .eq("task_id", task_id)
      .eq("user_id", user_id);
    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    if (count !== 1) {
      return res
        .status(200)
        .send({ message: "Not creator of task", is_creator: false });
    }
    return res
      .status(200)
      .send({ message: "Creator of task", is_creator: true });
  },
);

app.post(
  "/api/edit-profile",
  body("username")
    .notEmpty()
    .withMessage("Username is required")
    .isString()
    .withMessage("Username must be a string"),
  validateFunction,
  validateUser,

  async (req, res) => {
    const { username } = req.body;
    const { user_id } = res.locals.validate_user_payload;
    const { error } = await supabase
      .from("users")
      .update({ username: username })
      .eq("user_id", user_id);

    if (error) {
      console.log(error);
      return res.status(400).send({ message: "Database error" });
    }
    res.status(200).send({ message: "Username changed" });
  },
);
