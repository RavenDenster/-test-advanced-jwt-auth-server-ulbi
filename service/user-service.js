const userModel = require("../models/user-model")
const bcrypt = require('bcrypt')
const uuid = require('uuid')
const mailService = require('./mail-service')
const tokenService = require('./token-service')
const UserDto = require('../dtos/user-dto')
const ApiError = require('../exceptions/api-error')

class UserService {
    async registration(email, password) {
        const candidate = await userModel.findOne({email})
        if(candidate) {
            throw ApiError.BadRequest(`Пользователь с почтовым адресом ${email} уже существует`)
        }
        const hasPassword = await bcrypt.hash(password, 3)
        const activationLink = uuid.v4()

        const user = await userModel.create({email, password: hasPassword, activationLink})
        await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`)

        const useDto = new UserDto(user)
        const tokens = tokenService.generateTokens({...useDto})
        await tokenService.saveToken(useDto._id, tokens.refreshToken)
        return { ...tokens, user: useDto}
    } 

    async activate(activationLink) { // при переходе по эндпойнту выдаётся тру
        const user = await userModel.findOne({activationLink})
        if(!user) {
            throw ApiError.BadRequest('неккоректная ссылка активация0')
        } 
        user.isActivated = true
        await user.save()
    } 

    async login(email, password) {
        const user = await userModel.findOne({email})
        if(!user) {
            throw ApiError.BadRequest('Пользователь с таким email не найден')
        }
        const isPassEquals = await bcrypt.compare(password, user.password)
        if(!isPassEquals) {
            throw ApiError.BadRequest('неверный пароль')
        } 
        const userDto = new UserDto(user)
        const tokens = tokenService.generateTokens({...userDto})
        await tokenService.saveoken(userDto._id, tokens.refreshToken)
        return { ...tokens,user: userDto}
    }

    async logout(refreshToken) {
        const token = await tokenService.removeToken(refreshToken)
        return token
    }

    async refresh(refreshToken) {
        if(!refreshToken) {
            throw ApiError.UnauthorizedError()
        }
        const userData = tokenService.validateRefreshToken(refreshToken)
        const tokenFromDb = await tokenService.findToken(refreshToken)
        if(!userData || !tokenFromDb) {
            throw ApiError.UnauthorizedError()
        }
        const user = await userModel.findById(userData._id)
        const userDto = new UserDto(user)
        const tokens = tokenService.generateTokens({...userDto})

        await tokenService.saveToken(userDto._id, tokens.refreshToken)
        return { ...tokens,user: userDto}
    }

    async getAllUsers() {
        const users = await userModel.find()
        return users
    }
}

module.exports = new UserService()