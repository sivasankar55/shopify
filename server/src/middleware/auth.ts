import { getAuth } from "@clerk/express";
import type { Request,Response,NextFunction } from "express";
import { AppError } from "../utils/AppError";
import { User } from "../models/User";
import { asyncHandler } from "../utils/asyncHandler";

// to check the user is authenticated or not
export function requireAuth(req:Request, _res: Response, next: NextFunction) {
    const {userId} = getAuth(req)

    if(!userId) {
        return next(new AppError(401,"User is not logged in. Means unauth user!"))
    }

    next();
}

// if the user is authenticated then search the user in db
export async function getDbUserFromReq(req: Request) {
     const {userId} = getAuth(req);

     if(!userId) {
        throw new AppError(401, "User is not logged in. Means unauth user!")
     }

     const dbUser = await User.findOne({clerkUserId : userId}) 

     if(!dbUser) {
        throw new AppError(404, "User not found in the DB")
     }

     return dbUser;
}


// to check the current user have the admin or not 
export const  requiredAdmin = asyncHandler(
    async(req: Request, _res: Response, next: NextFunction) => {
        const extractCurrentDbUser = await getDbUserFromReq(req);

        if(extractCurrentDbUser.role !== "admin") {
            throw new AppError(403, "Admin access only");
        }

        next();
    }
);