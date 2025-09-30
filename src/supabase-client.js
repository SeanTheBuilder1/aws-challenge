import { createClient } from "@supabase/supabase-js";
import "dotenv/config";
const supabase_url = process.env.SUPABASE_URL;
const supabase_key = process.env.SUPABASE_KEY;
const supabase_service_role_key = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabase_url, supabase_service_role_key, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
  },
});
export default supabase;
