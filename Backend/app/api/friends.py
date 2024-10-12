from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import friend, user
from typing import List
from pydantic import BaseModel

router = APIRouter()

class FriendRequestCreate(BaseModel):
    receiver_ms_id: str

class FriendResponse(BaseModel):
    id: int
    username: str
    ms_id: str

@router.post("/request", response_model=dict)
def send_friend_request(request: FriendRequestCreate, requester_id: int, db: Session = Depends(get_db)):
    receiver = db.query(user.User).filter(user.User.ms_id == request.receiver_ms_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")

    existing_request = db.query(friend.FriendRequest).filter(
        (friend.FriendRequest.requester_id == requester_id) & 
        (friend.FriendRequest.receiver_id == receiver.id)
    ).first()

    if existing_request:
        raise HTTPException(status_code=400, detail="Friend request already sent")

    friend_request = friend.FriendRequest(requester_id=requester_id, receiver_id=receiver.id)
    db.add(friend_request)
    db.commit()
    return {"msg": "Friend request sent"}

@router.post("/accept/{request_id}", response_model=dict)
def accept_friend_request(request_id: int, user_id: int, db: Session = Depends(get_db)):
    friend_request = db.query(friend.FriendRequest).filter(friend.FriendRequest.id == request_id).first()
    if not friend_request or friend_request.receiver_id != user_id:
        raise HTTPException(status_code=404, detail="Friend request not found")
    
    if friend_request.is_accepted:
        raise HTTPException(status_code=400, detail="Friend request already accepted")

    friend_request.is_accepted = True
    db.commit()
    return {"msg": "Friend request accepted"}

@router.get("/list", response_model=List[FriendResponse])
def list_friends(user_id: int, db: Session = Depends(get_db)):
    friends = db.query(user.User).join(friend.FriendRequest, 
        ((friend.FriendRequest.requester_id == user_id) & (friend.FriendRequest.receiver_id == user.User.id)) |
        ((friend.FriendRequest.receiver_id == user_id) & (friend.FriendRequest.requester_id == user.User.id))
    ).filter(friend.FriendRequest.is_accepted == True).all()

    return [FriendResponse(id=f.id, username=f.username, ms_id=f.ms_id) for f in friends]

@router.delete("/remove/{friend_id}", response_model=dict)
def remove_friend(friend_id: int, user_id: int, db: Session = Depends(get_db)):
    friendship = db.query(friend.FriendRequest).filter(
        (((friend.FriendRequest.requester_id == user_id) & (friend.FriendRequest.receiver_id == friend_id)) |
        ((friend.FriendRequest.receiver_id == user_id) & (friend.FriendRequest.requester_id == friend_id))) &
        (friend.FriendRequest.is_accepted == True)
    ).first()

    if not friendship:
        raise HTTPException(status_code=404, detail="Friendship not found")

    db.delete(friendship)
    db.commit()
    return {"msg": "Friend removed successfully"}