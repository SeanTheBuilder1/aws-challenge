import { createClient } from "@supabase/supabase-js";
import "dotenv/config";
const supabase_url = process.env.SUPABASE_URL;
const supabase_key = process.env.SUPABASE_KEY;
const supabase = createClient(supabase_url, supabase_key);
export default supabase;
