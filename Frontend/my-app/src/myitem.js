import React from 'react';




class Item extends React.Component{
    clickme(){
        this.setState({
            clicks:this.state.clicks+1
        })
        alert("i was clicked")
    }
    constructor(props){
        super(props)
        this.state={
            clicks:0
        }
    }
    render(){
      return(
        <div>
            <h1 onClick={()=>this.clickme()}>Welcome to React Learning with {this.props.name} & {this.props.Name}</h1>
            <h2 >Hello from Raunak Palewar</h2>
            <span>
                {this.state.clicks} number of clicks
            </span>
        </div>
      )
    }
  }

export default Item;