export const UserRolesEnum = {
  ADMIN: "ADMIN",
  USER: "USER",
};

export const AvailableUserRoles = Object.values(UserRolesEnum);

export const UserLoginType = {
  GOOGLE: "GOOGLE",
  GITHUB: "GITHUB",
  EMAIL: "EMAIL",
};

export const AvailableSocialLogins = Object.values(UserLoginType);

export const DB_NAME = "authentication";
